#!/usr/bin/env bash
set -e

# WireGuard 接口名
WG_IF="wg0"

if [[ $EUID -ne 0 ]]; then
  echo "请用 root 运行这个脚本： sudo bash wg-menu.sh"
  exit 1
fi

install_wireguard() {
  echo "[*] 检查 WireGuard 及相关依赖..."

  # Debian 需要的包
  NEED_PKGS=(wireguard wireguard-tools iproute2 iptables resolvconf)
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

configure_exit() {
  echo "==== 配置为【出口服务器】（有公网 IP 的那台） ===="

  install_wireguard

  read -rp "出口服务器 WireGuard 内网 IP (默认 10.0.0.1/24): " WG_ADDR
  WG_ADDR=${WG_ADDR:-10.0.0.1/24}

  read -rp "入口服务器 WireGuard 内网 IP (默认 10.0.0.2/32): " ENTRY_WG_IP
  ENTRY_WG_IP=${ENTRY_WG_IP:-10.0.0.2/32}

  # 自动探测默认外网网卡
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

  # 开启 IPv4 转发
  if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi
  sysctl -p >/dev/null

  cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_ADDR}
ListenPort = 51820
PrivateKey = ${EXIT_PRIVATE_KEY}

# NAT 转发，让入口服务器的流量都能出网
PostUp   = iptables -A FORWARD -i ${WG_IF} -j ACCEPT; iptables -A FORWARD -o ${WG_IF} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${OUT_IF} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_IF} -j ACCEPT; iptables -D FORWARD -o ${WG_IF} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${OUT_IF} -j MASQUERADE

[Peer]
# 入口服务器
PublicKey = ${ENTRY_PUBLIC_KEY}
AllowedIPs = ${ENTRY_WG_IP}
EOF

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

  read -rp "出口服务器公网 IP: " EXIT_PUBLIC_IP
  if [ -z "$EXIT_PUBLIC_IP" ]; then
    echo "出口服务器公网 IP 不能为空"
    exit 1
  fi

  read -rp "出口服务器 WireGuard 端口 (默认 51820): " EXIT_PUBLIC_PORT
  EXIT_PUBLIC_PORT=${EXIT_PUBLIC_PORT:-51820}

  read -rp "请输入【出口服务器公钥】: " EXIT_PUBLIC_KEY
  EXIT_PUBLIC_KEY=${EXIT_PUBLIC_KEY:-CHANGE_ME_EXIT_PUBLIC_KEY}

  mkdir -p /etc/wireguard
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

  cat > /etc/wireguard/${WG_IF}.conf <<EOF
[Interface]
Address = ${WG_ADDR}
PrivateKey = ${ENTRY_PRIVATE_KEY}
DNS = 8.8.8.8

[Peer]
# 出口服务器
PublicKey = ${EXIT_PUBLIC_KEY}
Endpoint = ${EXIT_PUBLIC_IP}:${EXIT_PUBLIC_PORT}
# 如只想内网互通，可改为 ${EXIT_WG_IP}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

  chmod 600 /etc/wireguard/${WG_IF}.conf

  systemctl enable wg-quick@${WG_IF}.service >/dev/null 2>&1 || true
  systemctl restart wg-quick@${WG_IF}.service || true

  echo
  echo "入口服务器配置完成，当前状态："
  wg show || true

  echo
  echo "⚠ 请把上面显示的【入口服务器 公钥】复制到出口服务器，"
  echo "  再在出口服务器上运行本脚本，选【1 出口服务器】重新写入 Peer。"
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
  echo "==== 卸载 WireGuard（删除配置和程序） ===="
  echo "此操作将会："
  echo "  - 停止 wg-quick@${WG_IF} 服务"
  echo "  - 取消开机自启"
  echo "  - 删除 /etc/wireguard/${WG_IF}.conf 和生成的密钥文件"
  echo "  - 卸载 wireguard 与 wireguard-tools 包（保留 iptables/resolvconf）"
  echo
  read -rp "确认卸载？(y/N): " confirm
  case "$confirm" in
    y|Y)
      systemctl stop wg-quick@${WG_IF}.service 2>/dev/null || true
      systemctl disable wg-quick@${WG_IF}.service 2>/dev/null || true

      rm -f /etc/wireguard/${WG_IF}.conf \
            /etc/wireguard/exit_private.key /etc/wireguard/exit_public.key \
            /etc/wireguard/entry_private.key /etc/wireguard/entry_public.key

      rmdir /etc/wireguard 2>/dev/null || true

      export DEBIAN_FRONTEND=noninteractive
      apt remove -y wireguard wireguard-tools || true
      apt autoremove -y || true

      echo "✅ WireGuard 已卸载，配置文件已删除。"
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
  echo "7) 卸载 WireGuard"
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
