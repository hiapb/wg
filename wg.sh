#!/usr/bin/env bash
set -e

WG_IF="wg0"

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行这个脚本： sudo bash wg.sh"
  exit 1
fi

install_wireguard() {
  echo "[*] 检查 WireGuard 及相关依赖..."
  NEED_PKGS=(wireguard wireguard-tools iproute2 iptables)
  MISSING_PKGS=()

  for pkg in "${NEED_PKGS[@]}"; do
    dpkg -s "$pkg" &>/dev/null || MISSING_PKGS+=("$pkg")
  done

  if [ ${#MISSING_PKGS[@]} -eq 0 ]; then
    echo "[*] 所有依赖已安装，跳过安装步骤。"
    return
  fi

  echo "[*] 将安装缺失的依赖包: ${MISSING_PKGS[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y "${MISSING_PKGS[@]}"
}

detect_public_ip() {
  for svc in "https://api.ipify.org" "https://ifconfig.me" "https://ipinfo.io/ip"; do
    ip=$(curl -4 -fsS "$svc" 2>/dev/null || true)
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

configure_exit() {
  echo "==== 配置为【出口服务器】（有公网 IP 的那台） ===="

  install_wireguard

  PUB_IP_DETECTED=$(detect_public_ip || true)
  if [[ -n "$PUB_IP_DETECTED" ]]; then
    echo "[*] 检测到出口服务器公网 IP 可能是：$PUB_IP_DETECTED"
  else
    echo "[*] 未能自动检测公网 IP，请参考服务商面板上的 IP。"
  fi

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.1/24}

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/32): " ENTRY_WG_IP
  ENTRY_WG_IP=${ENTRY_WG_IP:-10.0.0.2/32}

  DEFAULT_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
  read -rp "出口服务器对外网卡名(默认 ${DEFAULT_IF:-eth0}): " OUT_IF
  OUT_IF=${OUT_IF:-${DEFAULT_IF:-eth0}}

  mkdir -p /etc/wireguard
  cd /etc/wireguard

  if [ ! -f exit_private.key ]; then
    echo "[*] 生成出口服务器密钥..."
    umask 077
    wg genkey | tee exit_private.key | wg pubkey > exit_public.key
  fi

  EXIT_PRIVATE_KEY=$(cat exit_private.key)
  EXIT_PUBLIC_KEY=$(cat exit_public.key)

  echo
  echo "====== 出口服务器 公钥（发给入口服务器用）======"
  echo "${EXIT_PUBLIC_KEY}"
  echo "================================================"
  echo

  read -rp "请输入【入口服务器公钥】（如果暂时没有可以直接回车跳过）: " ENTRY_PUBLIC_KEY
  ENTRY_PUBLIC_KEY=${ENTRY_PUBLIC_KEY:-CHANGE_ME_ENTRY_PUBLIC_KEY}

  if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi
  sysctl -p >/dev/null

  cat > /etc/wireguard/${WG_IF}.conf <<EOF_WG_EXIT
[Interface]
Address = ${WG_ADDR}
ListenPort = 51820
PrivateKey = ${EXIT_PRIVATE_KEY}

PostUp   = iptables -A FORWARD -i ${WG_IF} -j ACCEPT; iptables -A FORWARD -o ${WG_IF} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${OUT_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_IF} -j ACCEPT; iptables -D FORWARD -o ${WG_IF} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${OUT_IF} -j MASQUERADE

[Peer]
PublicKey = ${ENTRY_PUBLIC_KEY}
AllowedIPs = ${ENTRY_WG_IP}
EOF_WG_EXIT

  chmod 600 /etc/wireguard/${WG_IF}.conf
  systemctl enable wg-quick@${WG_IF}.service >/dev/null 2>&1 || true
  systemctl restart wg-quick@${WG_IF}.service || true

  echo
  echo "出口服务器配置完成，当前状态："
  wg show || true

  echo
  echo "⚠ 如果刚才入口服务器公钥是占位符："
  echo "   等你拿到入口服务器公钥后，再次运行本脚本选择【1 出口服务器】，"
  echo "   重新输入入口服务器公钥即可覆盖配置。"
}

configure_entry() {
  echo "==== 配置为【入口服务器】（连出去的那台） ===="

  install_wireguard

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.2/24}

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/32): " EXIT_WG_IP
  EXIT_WG_IP=${EXIT_WG_IP:-10.0.0.1/32}

  SAVED_EXIT_IP=""
  if [[ -f /etc/wireguard/.exit_public_ip ]]; then
    SAVED_EXIT_IP=$(cat /etc/wireguard/.exit_public_ip 2>/dev/null || true)
  fi

  if [[ -n "$SAVED_EXIT_IP" ]]; then
    read -rp "出口服务器公网 IP (默认 ${SAVED_EXIT_IP}): " EXIT_PUBLIC_IP
    EXIT_PUBLIC_IP=${EXIT_PUBLIC_IP:-$SAVED_EXIT_IP}
  else
    read -rp "出口服务器公网 IP: " EXIT_PUBLIC_IP
  fi

  if [ -z "$EXIT_PUBLIC_IP" ]; then
    echo "出口服务器公网 IP 不能为空"
    exit 1
  fi

  mkdir -p /etc/wireguard
  echo "$EXIT_PUBLIC_IP" > /etc/wireguard/.exit_public_ip

  read -rp "出口服务器 WireGuard 端口 (默认 51820): " EXIT_PUBLIC_PORT
  EXIT_PUBLIC_PORT=${EXIT_PUBLIC_PORT:-51820}

  read -rp "请输入【出口服务器公钥】: " EXIT_PUBLIC_KEY
  EXIT_PUBLIC_KEY=${EXIT_PUBLIC_KEY:-CHANGE_ME_EXIT_PUBLIC_KEY}

  ALLOWED_IPS="${EXIT_WG_IP}"

  cd /etc/wireguard

  if [ ! -f entry_private.key ]; then
    echo "[*] 生成入口服务器密钥..."
    umask 077
    wg genkey | tee entry_private.key | wg pubkey > entry_public.key
  fi

  ENTRY_PRIVATE_KEY=$(cat entry_private.key)
  ENTRY_PUBLIC_KEY=$(cat entry_public.key)

  echo
  echo "====== 入口服务器 公钥（发给出口服务器用）======"
  echo "${ENTRY_PUBLIC_KEY}"
  echo "================================================"
  echo

  cat > /etc/wireguard/${WG_IF}.conf <<EOF_WG_ENTRY
[Interface]
Address = ${WG_ADDR}
PrivateKey = ${ENTRY_PRIVATE_KEY}

# 策略路由：让“发往出口公网 IP 的所有流量（除了 UDP 51820 握手）”走 WG
PostUp   = ip rule show | grep -q "fwmark 0x1 lookup 100" || ip rule add fwmark 0x1 lookup 100; \
           ip route replace ${EXIT_PUBLIC_IP}/32 dev ${WG_IF} table 100; \
           iptables -t mangle -C OUTPUT -d ${EXIT_PUBLIC_IP} -p udp ! --dport 51820 -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A OUTPUT -d ${EXIT_PUBLIC_IP} -p udp ! --dport 51820 -j MARK --set-mark 0x1; \
           iptables -t mangle -C OUTPUT -d ${EXIT_PUBLIC_IP} ! -p udp -j MARK --set-mark 0x1 2>/dev/null || iptables -t mangle -A OUTPUT -d ${EXIT_PUBLIC_IP} ! -p udp -j MARK --set-mark 0x1
PostDown = iptables -t mangle -D OUTPUT -d ${EXIT_PUBLIC_IP} -p udp ! --dport 51820 -j MARK --set-mark 0x1 2>/dev/null || true; \
           iptables -t mangle -D OUTPUT -d ${EXIT_PUBLIC_IP} ! -p udp -j MARK --set-mark 0x1 2>/dev/null || true; \
           ip route del ${EXIT_PUBLIC_IP}/32 dev ${WG_IF} table 100 2>/dev/null || true; \
           ip rule del fwmark 0x1 lookup 100 2>/dev/null || true

[Peer]
PublicKey = ${EXIT_PUBLIC_KEY}
Endpoint = ${EXIT_PUBLIC_IP}:${EXIT_PUBLIC_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25
EOF_WG_ENTRY

  chmod 600 /etc/wireguard/${WG_IF}.conf
  systemctl enable wg-quick@${WG_IF}.service >/dev/null 2>&1 || true
  systemctl restart wg-quick@${WG_IF}.service || true

  echo
  echo "入口服务器配置完成，当前状态："
  wg show || true

  echo
  echo "✅ 当前模式："
  echo "   - 访问出口 WG 内网 IP：${EXIT_WG_IP} → 走 WireGuard 内网"
  echo "   - 访问出口公网 IP：${EXIT_PUBLIC_IP} 的所有流量（除 UDP 51820 握手）→ 自动打标记 → 走 WireGuard"
  echo "   - UDP 51820 握手仍走 eth0，不死锁，不改默认路由、不改 DNS。"
  echo
  echo "⚠ 把上面显示的【入口服务器 公钥】复制到出口服务器，"
  echo "  在出口服务器上运行本脚本选【1 出口服务器】写入 Peer。"
}

show_status() {
  echo "==== WireGuard 状态 ===="
  if command -v wg >/dev/null 2>&1; then
    wg show || echo "wg0 似乎还没配置/启动。"
  else
    echo "系统未安装 WireGuard。"
  fi
}

start_wg() {
  echo "[*] 启动 WireGuard (${WG_IF})..."
  systemctl start wg-quick@${WG_IF}.service || true
  wg show || true
}

stop_wg() {
  echo "[*] 停止 WireGuard (${WG_IF})..."
  systemctl stop wg-quick@${WG_IF}.service || true
  wg show || true
}

restart_wg() {
  echo "[*] 重启 WireGuard (${WG_IF})..."
  systemctl restart wg-quick@${WG_IF}.service || true
  wg show || true
}

uninstall_wg() {
  echo "==== 卸载 WireGuard（删除配置和程序 + 本脚本） ===="
  echo "此操作将会："
  echo "  - 停止 wg-quick@${WG_IF} 服务并取消开机自启"
  echo "  - 删除 /etc/wireguard 内的配置和密钥"
  echo "  - 移除策略路由 / iptables 标记规则"
  echo "  - 卸载 wireguard 与 wireguard-tools"
  echo "  - 删除当前脚本文件：$0"
  echo
  read -rp "确认卸载并删除脚本？(y/N): " confirm
  case "$confirm" in
    y|Y)
      systemctl stop wg-quick@${WG_IF}.service 2>/dev/null || true
      systemctl disable wg-quick@${WG_IF}.service 2>/dev/null || true

      # 清理策略路由和 mangle 规则（入口机上有效，出口机上无影响）
      if [[ -f /etc/wireguard/.exit_public_ip ]]; then
        EXIT_PUBLIC_IP=$(cat /etc/wireguard/.exit_public_ip 2>/dev/null || true)
        if [[ -n "$EXIT_PUBLIC_IP" ]]; then
          iptables -t mangle -D OUTPUT -d ${EXIT_PUBLIC_IP} -p udp ! --dport 51820 -j MARK --set-mark 0x1 2>/dev/null || true
          iptables -t mangle -D OUTPUT -d ${EXIT_PUBLIC_IP} ! -p udp -j MARK --set-mark 0x1 2>/dev/null || true
          ip route del ${EXIT_PUBLIC_IP}/32 dev ${WG_IF} table 100 2>/dev/null || true
        fi
      fi
      ip rule del fwmark 0x1 lookup 100 2>/dev/null || true
      ip route flush table 100 2>/dev/null || true

      rm -f /etc/wireguard/${WG_IF}.conf \
            /etc/wireguard/exit_private.key /etc/wireguard/exit_public.key \
            /etc/wireguard/entry_private.key /etc/wireguard/entry_public.key \
            /etc/wireguard/.exit_public_ip 2>/dev/null || true
      rmdir /etc/wireguard 2>/dev/null || true

      export DEBIAN_FRONTEND=noninteractive
      apt remove -y wireguard wireguard-tools 2>/dev/null || true
      apt autoremove -y 2>/dev/null || true

      echo "✅ WireGuard 已卸载，配置文件已删除。"
      echo "✅ 正在删除当前脚本：$0"
      rm -f "$0" 2>/dev/null || true
      echo "✅ 脚本已删除，退出。"
      exit 0
      ;;
    *)
      echo "已取消卸载。"
      ;;
  esac
}

while true; do
  echo
  echo "================ WireGuard 一键脚本 ================"
  echo "1) 配置为 出口服务器"
  echo "2) 配置为 入口服务器"
  echo "3) 查看 WireGuard 状态"
  echo "4) 启动 WireGuard"
  echo "5) 停止 WireGuard"
  echo "6) 重启 WireGuard"
  echo "7) 卸载 WireGuard（并删除脚本）"
  echo "0) 退出"
  echo "===================================================="
  read -rp "请选择: " choice

  case "$choice" in
    1) configure_exit ;;
    2) configure_entry ;;
    3) show_status ;;
    4) start_wg ;;
    5) stop_wg ;;
    6) restart_wg ;;
    7) uninstall_wg ;;
    0) exit 0 ;;
    *) echo "无效选项" ;;
  esac
done
