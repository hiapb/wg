#!/usr/bin/env bash
set -Eeuo pipefail

# WireGuard entry/exit deployment and policy-routing manager.

APP_NAME="wg-manager"
WG_IF="wg0"
WG_DIR="/etc/wireguard"
BASE_DIR="/etc/${APP_NAME}"
STATE_DIR="${BASE_DIR}/state"
WG_CONFIG="${WG_DIR}/${WG_IF}.conf"
WG_MARKER="${WG_DIR}/.${APP_NAME}.managed"

ROLE_FILE="${STATE_DIR}/role"
MODE_FILE="${STATE_DIR}/mode"
WG_PRIVATE_KEY_FILE="${STATE_DIR}/wg_private.key"
WG_PUBLIC_KEY_FILE="${STATE_DIR}/wg_public.key"
PEER_PUBLIC_KEY_FILE="${STATE_DIR}/peer_public.key"
REMOTE_HOST_FILE="${STATE_DIR}/remote_host"
REMOTE_PORT_FILE="${STATE_DIR}/remote_port"
ENDPOINT_IP_FILE="${STATE_DIR}/endpoint_ipv4"
WG_ADDRESS_FILE="${STATE_DIR}/wg_address"
PEER_ADDRESS_FILE="${STATE_DIR}/peer_address"
WAN_IF_FILE="${STATE_DIR}/wan_if"
SSH_PORTS_FILE="${STATE_DIR}/ssh_ports"
PORTS_FILE="${STATE_DIR}/ports"

MANAGER_BIN="/usr/local/sbin/wg-manager"
ROUTING_SERVICE="wg-manager-routing.service"
HEALTH_SERVICE="wg-manager-healthcheck.service"
HEALTH_TIMER="wg-manager-healthcheck.timer"
HEALTH_FAILURE_FILE="/run/wg-manager-health-failures"

ROUTE_TABLE_ID="51820"
FW_MARK="0x1"
LOCAL_CONN_MARK="0x2"
CARRIER_MARK="0x66"
CARRIER_RULE_PRIORITY="100"
WAN_BIND_RULE_PRIORITY="90"
MANGLE_OUT_CHAIN="WGN_OUT"
MANGLE_PRE_CHAIN="WGN_PRE"
NYANPASS_IN_CHAIN="WGN_NYAN_IN"
NYANPASS_OUT_CHAIN="WGN_NYAN_OUT"
INPUT_CHAIN="WGN_INPUT"

DEFAULT_WG_PORT="51820"
DEFAULT_EXIT_ADDRESS="10.0.0.1/24"
DEFAULT_ENTRY_ADDRESS="10.0.0.2/24"
WG_SAFE_MTU="1380"
HEALTH_HANDSHAKE_MAX_AGE="180"
HEALTH_FAILURE_THRESHOLD="3"

if [[ "${EUID:-$(id -u)}" -ne 0 && "${1:-}" != "--help" && "${1:-}" != "-h" ]]; then
  printf '请使用 root 运行：sudo bash %s\n' "$0" >&2
  exit 1
fi

print_block() { printf '\n==================================================\n%s\n==================================================\n' "$1"; }
info() { printf '[信息] %s\n' "$*"; }
ok() { printf '[完成] %s\n' "$*"; }
warn() { printf '[注意] %s\n' "$*" >&2; }
err() { printf '[错误] %s\n' "$*" >&2; }
print_ok() { printf '✅ %s\n' "$*"; }
print_warn() { printf '⚠️  %s\n' "$*" >&2; }
print_err() { printf '❌ %s\n' "$*" >&2; }

ensure_dirs() {
  install -d -m 700 "$BASE_DIR" "$STATE_DIR" "$WG_DIR"
}

write_value() {
  local file="$1" value="$2"
  ensure_dirs
  printf '%s\n' "$value" > "$file"
  chmod 600 "$file" 2>/dev/null || true
}

read_value() {
  local file="$1"
  [[ -s "$file" ]] && tr -d '\r\n' < "$file" || true
}

role() { read_value "$ROLE_FILE"; }
get_role() { role; }
set_role() { write_value "$ROLE_FILE" "$1"; }
mode() {
  local value
  value="$(read_value "$MODE_FILE")"
  printf '%s\n' "${value:-split}"
}
get_current_mode() { mode; }
set_mode_flag() { write_value "$MODE_FILE" "$1"; }

valid_port() {
  local port="${1:-}"
  [[ "$port" =~ ^[0-9]+$ && ${#port} -le 5 ]] || return 1
  ((10#$port >= 1 && 10#$port <= 65535))
}

valid_wg_key() { [[ "${1:-}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }

valid_ipv4() {
  local value="${1:-}" a b c d octet
  IFS=. read -r a b c d <<< "$value"
  [[ -n "$a" && -n "$b" && -n "$c" && -n "$d" && "$value" != *.*.*.*.* ]] || return 1
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] && ((10#$octet <= 255)) || return 1
  done
}

valid_ipv4_cidr() {
  local value="${1:-}" address prefix
  [[ "$value" == */* ]] || return 1
  address="${value%%/*}"; prefix="${value##*/}"
  valid_ipv4 "$address" && [[ "$prefix" =~ ^[0-9]{1,2}$ ]] && ((10#$prefix >= 1 && 10#$prefix <= 32))
}

valid_host() {
  valid_ipv4 "${1:-}" && return 0
  [[ "${1:-}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}

normalize_host() {
  local value="${1:-}"
  value="${value#http://}"; value="${value#https://}"; value="${value%%/*}"
  printf '%s\n' "$value"
}

network_cidr() {
  local cidr="$1" address prefix a b c d
  address="${cidr%%/*}"; prefix="${cidr##*/}"
  IFS=. read -r a b c d <<< "$address"
  case "$prefix" in
    8) printf '%s.0.0.0/8\n' "$a" ;;
    16) printf '%s.%s.0.0/16\n' "$a" "$b" ;;
    24) printf '%s.%s.%s.0/24\n' "$a" "$b" "$c" ;;
    32) printf '%s/32\n' "$address" ;;
    *) printf '%s\n' "$cidr" ;;
  esac
}

get_wan_if() {
  local value
  value="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  printf '%s\n' "${value:-eth0}"
}

detect_ssh_ports() {
  {
    printf '%s\n' "${SSH_CONNECTION:-}" | awk 'NF >= 4 {print $4}'
    if command -v ss >/dev/null 2>&1; then
      ss -H -ltnp 2>/dev/null | awk '
        /users:\(\("(sshd|dropbear)"/ {address=$4; sub(/^.*:/,"",address); print address}
      ' || true
    fi
    if command -v sshd >/dev/null 2>&1; then
      sshd -T 2>/dev/null | awk '$1=="port" {print $2}' || true
    elif [[ -x /usr/sbin/sshd ]]; then
      /usr/sbin/sshd -T 2>/dev/null | awk '$1=="port" {print $2}' || true
    fi
    if [[ -r /etc/default/dropbear ]]; then
      sed -n 's/^[[:space:]]*DROPBEAR_PORT[[:space:]]*=[[:space:]]*["'\'' ]*\([0-9][0-9]*\).*/\1/p' /etc/default/dropbear
    fi
    printf '22\n'
  } | awk '/^[0-9]+$/ && $1>=1 && $1<=65535 && !seen[$1]++ {print; count++; if(count==15) exit}'
}

refresh_ssh_ports() {
  local ports
  ports="$(detect_ssh_ports | paste -sd, -)"
  ports="${ports:-22}"
  write_value "$SSH_PORTS_FILE" "$ports"
  printf '%s\n' "$ports"
}

protected_ssh_ports_csv() {
  local ports
  ports="$(read_value "$SSH_PORTS_FILE")"
  printf '%s\n' "${ports:-22}"
}

is_protected_ssh_port() {
  local port="$1" ports
  ports=",$(protected_ssh_ports_csv),"
  [[ "$ports" == *",${port},"* ]]
}

resolve_ipv4s() {
  local host="$1"
  if valid_ipv4 "$host"; then
    printf '%s\n' "$host"
  else
    getent ahostsv4 "$host" 2>/dev/null | awk '!seen[$1]++ {print $1}' || true
  fi
}

install_packages() {
  command -v apt-get >/dev/null 2>&1 || { err '仅支持 Debian/Ubuntu 的 apt-get 系统'; return 1; }
  export DEBIAN_FRONTEND=noninteractive
  info '安装 WireGuard 和网络依赖...'
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y wireguard-tools iproute2 iptables iputils-ping ca-certificates >/dev/null 2>&1
}

ensure_ip_forward() {
  printf '1\n' > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  if [[ -f /etc/sysctl.conf ]] && ! grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*1[[:space:]]*$' /etc/sysctl.conf; then
    printf '\n# %s\nnet.ipv4.ip_forward=1\n' "$APP_NAME" >> /etc/sysctl.conf
  fi
  sysctl -p >/dev/null 2>&1 || true
}

ensure_wg_conf_is_owned() {
  if [[ -e "$WG_CONFIG" && ! -e "$WG_MARKER" ]]; then
    err "检测到未由本脚本管理的 ${WG_CONFIG}，已停止以避免覆盖。"
    return 1
  fi
  touch "$WG_MARKER"
  chmod 600 "$WG_MARKER"
}

ensure_local_wg_identity() {
  local role_label="$1" supplied_private private_key public_key old_public
  ensure_dirs
  old_public="$(read_value "$WG_PUBLIC_KEY_FILE")"
  while true; do
    if [[ -s "$WG_PRIVATE_KEY_FILE" ]]; then
      read -rp "自定义${role_label} WireGuard 私钥（回车复用现有）: " supplied_private
    else
      read -rp "自定义${role_label} WireGuard 私钥（回车自动生成）: " supplied_private
    fi
    supplied_private="${supplied_private//[[:space:]]/}"
    if [[ -n "$supplied_private" ]]; then
      private_key="$supplied_private"
    elif [[ -s "$WG_PRIVATE_KEY_FILE" ]]; then
      private_key="$(read_value "$WG_PRIVATE_KEY_FILE")"
    else
      private_key="$(wg genkey)"
    fi
    public_key="$(printf '%s\n' "$private_key" | wg pubkey 2>/dev/null || true)"
    if valid_wg_key "$private_key" && valid_wg_key "$public_key"; then
      write_value "$WG_PRIVATE_KEY_FILE" "$private_key"
      write_value "$WG_PUBLIC_KEY_FILE" "$public_key"
      if [[ -n "$old_public" && "$old_public" != "$public_key" ]]; then
        print_warn '本机 WireGuard 公钥已改变，必须在对端更新为新公钥'
      fi
      return 0
    fi
    print_err 'WireGuard 私钥无效，请重新输入'
    supplied_private=''
  done
}

prompt_wg_key() {
  local label="$1" file="$2" value
  while true; do
    read -rp "${label} WireGuard 公钥: " value
    value="${value:-$(read_value "$file")}"
    if valid_wg_key "$value"; then write_value "$file" "$value"; return 0; fi
    print_err 'WireGuard 公钥格式无效'
  done
}

select_endpoint_ipv4() {
  local host="$1" rotate="${2:-n}" current ip first='' next='' seen=n
  current="$(read_value "$ENDPOINT_IP_FILE")"
  while read -r ip; do
    valid_ipv4 "$ip" || continue
    [[ -z "$first" ]] && first="$ip"
    if [[ "$rotate" == y && "$seen" == y && -z "$next" ]]; then next="$ip"; fi
    [[ "$ip" == "$current" ]] && seen=y
  done < <(resolve_ipv4s "$host")
  [[ -n "$first" ]] || return 1
  if [[ "$rotate" == y && -n "$next" ]]; then printf '%s\n' "$next"; else printf '%s\n' "$first"; fi
}

policy_rule_exists() {
  local wanted_mark="$1" wanted_table="$2" wanted_priority="${3:-}"
  ip rule show 2>/dev/null | awk -v mark="$wanted_mark" -v table="$wanted_table" -v priority="$wanted_priority" '
    {
      p=$1; sub(/:$/,"",p); if(priority!="" && p!=priority) next
      mok=0; tok=0
      for(i=1;i<=NF;i++) {
        if($i=="fwmark" && i<NF) {split($(i+1),a,"/"); if(tolower(a[1])==tolower(mark)) mok=1}
        if(($i=="lookup" || $i=="table") && i<NF && $(i+1)==table) tok=1
      }
      if(mok && tok) found=1
    }
    END {exit(found?0:1)}'
}

carrier_policy_rule_exists() { policy_rule_exists "$CARRIER_MARK" main "$CARRIER_RULE_PRIORITY"; }
fw_policy_rule_exists() { policy_rule_exists "$FW_MARK" "$ROUTE_TABLE_ID"; }

wan_bind_policy_rule_exists() {
  local wan_if="$1"
  ip rule show 2>/dev/null | awk -v p="$WAN_BIND_RULE_PRIORITY" -v dev="$wan_if" '
    {q=$1; sub(/:$/,"",q); if(q!=p) next; ook=0; tok=0
     for(i=1;i<=NF;i++){if($i=="oif" && $(i+1)==dev) ook=1; if(($i=="lookup"||$i=="table") && $(i+1)=="main") tok=1}
     if(ook&&tok) found=1} END{exit(found?0:1)}'
}

ensure_wan_bind_policy_rule() {
  local wan_if
  wan_if="$(read_value "$WAN_IF_FILE")"
  [[ -n "$wan_if" ]] || { err '入口公网网卡未配置'; return 1; }
  wan_bind_policy_rule_exists "$wan_if" && return 0
  if ip rule show 2>/dev/null | awk -v p="${WAN_BIND_RULE_PRIORITY}:" '$1==p{found=1} END{exit(found?0:1)}'; then
    err "ip rule 优先级 ${WAN_BIND_RULE_PRIORITY} 已被占用"
    return 1
  fi
  ip rule add priority "$WAN_BIND_RULE_PRIORITY" oif "$wan_if" table main
  wan_bind_policy_rule_exists "$wan_if"
}

ensure_carrier_policy_rule() {
  carrier_policy_rule_exists && return 0
  if ip rule show 2>/dev/null | awk -v p="${CARRIER_RULE_PRIORITY}:" '$1==p{found=1} END{exit(found?0:1)}'; then
    err "ip rule 优先级 ${CARRIER_RULE_PRIORITY} 已被占用"
    return 1
  fi
  ip rule add priority "$CARRIER_RULE_PRIORITY" fwmark "$CARRIER_MARK" table main
  carrier_policy_rule_exists
}

clear_fw_policy_rules() {
  while fw_policy_rule_exists; do ip rule del fwmark "$FW_MARK" table "$ROUTE_TABLE_ID" 2>/dev/null || break; done
}

clear_carrier_policy_rule() {
  while carrier_policy_rule_exists; do ip rule del priority "$CARRIER_RULE_PRIORITY" fwmark "$CARRIER_MARK" table main 2>/dev/null || break; done
}

clear_wan_bind_policy_rule() {
  local wan_if
  wan_if="$(read_value "$WAN_IF_FILE")"
  [[ -n "$wan_if" ]] || return 0
  while wan_bind_policy_rule_exists "$wan_if"; do ip rule del priority "$WAN_BIND_RULE_PRIORITY" oif "$wan_if" table main 2>/dev/null || break; done
}

write_exit_wg_config() {
  local address peer_address private peer_public wan_if port peer_ip
  address="$(read_value "$WG_ADDRESS_FILE")"; peer_address="$(read_value "$PEER_ADDRESS_FILE")"
  private="$(read_value "$WG_PRIVATE_KEY_FILE")"; peer_public="$(read_value "$PEER_PUBLIC_KEY_FILE")"
  wan_if="$(read_value "$WAN_IF_FILE")"; port="$(read_value "$REMOTE_PORT_FILE")"
  peer_ip="${peer_address%%/*}"
  valid_ipv4_cidr "$address" && valid_ipv4_cidr "$peer_address" && valid_wg_key "$private" && \
    valid_port "$port" || { err '出口 WireGuard 配置字段无效'; return 1; }
  [[ -z "$peer_public" ]] || valid_wg_key "$peer_public" || { err '入口 WireGuard 公钥无效'; return 1; }
  ensure_wg_conf_is_owned
  cat > "$WG_CONFIG" <<EOF
[Interface]
Address = ${address}
ListenPort = ${port}
PrivateKey = ${private}
FwMark = ${CARRIER_MARK}
MTU = ${WG_SAFE_MTU}
PostUp = iptables -C FORWARD -i ${WG_IF} -o ${wan_if} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${WG_IF} -o ${wan_if} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT; iptables -C FORWARD -i ${wan_if} -o ${WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${wan_if} -o ${WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -C POSTROUTING -s ${peer_ip}/32 -o ${wan_if} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${peer_ip}/32 -o ${wan_if} -j MASQUERADE; iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D FORWARD -i ${WG_IF} -o ${wan_if} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -i ${wan_if} -o ${WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true; iptables -t nat -D POSTROUTING -s ${peer_ip}/32 -o ${wan_if} -j MASQUERADE 2>/dev/null || true; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
EOF
  if [[ -n "$peer_public" ]]; then
    cat >> "$WG_CONFIG" <<EOF

[Peer]
PublicKey = ${peer_public}
AllowedIPs = ${peer_ip}/32
EOF
  fi
  chmod 600 "$WG_CONFIG"
}

write_entry_wg_config() {
  local address peer_address private peer_public endpoint_ip endpoint_port wan_if
  address="$(read_value "$WG_ADDRESS_FILE")"; peer_address="$(read_value "$PEER_ADDRESS_FILE")"
  private="$(read_value "$WG_PRIVATE_KEY_FILE")"; peer_public="$(read_value "$PEER_PUBLIC_KEY_FILE")"
  endpoint_ip="$(read_value "$ENDPOINT_IP_FILE")"; endpoint_port="$(read_value "$REMOTE_PORT_FILE")"
  wan_if="$(read_value "$WAN_IF_FILE")"
  valid_ipv4_cidr "$address" && valid_ipv4_cidr "$peer_address" && valid_ipv4 "$endpoint_ip" && \
    valid_wg_key "$private" && valid_wg_key "$peer_public" && valid_port "$endpoint_port" || {
      err '入口 WireGuard 配置字段无效'
      return 1
    }
  ensure_wg_conf_is_owned
  cat > "$WG_CONFIG" <<EOF
[Interface]
Address = ${address}
PrivateKey = ${private}
FwMark = ${CARRIER_MARK}
Table = off
MTU = ${WG_SAFE_MTU}
PostUp = ip rule add priority ${WAN_BIND_RULE_PRIORITY} oif ${wan_if} table main 2>/dev/null || true; ip rule add priority ${CARRIER_RULE_PRIORITY} fwmark ${CARRIER_MARK} table main 2>/dev/null || true; ip rule add fwmark ${FW_MARK} table ${ROUTE_TABLE_ID} 2>/dev/null || true; ip route replace default dev ${WG_IF} table ${ROUTE_TABLE_ID}; iptables -t nat -C POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${WG_IF} -j MASQUERADE
PostDown = ip rule del priority ${WAN_BIND_RULE_PRIORITY} oif ${wan_if} table main 2>/dev/null || true; ip rule del priority ${CARRIER_RULE_PRIORITY} fwmark ${CARRIER_MARK} table main 2>/dev/null || true; ip rule del fwmark ${FW_MARK} table ${ROUTE_TABLE_ID} 2>/dev/null || true; ip route flush table ${ROUTE_TABLE_ID} 2>/dev/null || true; iptables -t nat -D POSTROUTING -o ${WG_IF} -j MASQUERADE 2>/dev/null || true

[Peer]
PublicKey = ${peer_public}
Endpoint = ${endpoint_ip}:${endpoint_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 20
EOF
  chmod 600 "$WG_CONFIG"
}

refresh_entry_endpoint() {
  local rotate="${1:-n}" host port ip peer_public
  [[ "$(role)" == entry ]] || return 0
  host="$(read_value "$REMOTE_HOST_FILE")"; port="$(read_value "$REMOTE_PORT_FILE")"
  peer_public="$(read_value "$PEER_PUBLIC_KEY_FILE")"
  ip="$(select_endpoint_ipv4 "$host" "$rotate")" || {
    warn "暂时无法解析 WireGuard 出口域名 ${host}，保留当前端点"
    return 1
  }
  if ip link show "$WG_IF" >/dev/null 2>&1; then
    wg set "$WG_IF" peer "$peer_public" endpoint "${ip}:${port}"
  fi
  write_value "$ENDPOINT_IP_FILE" "$ip"
  write_entry_wg_config
  info "WireGuard 端点已更新为 ${ip}:${port}"
}

setup_host_firewall() {
  local current port
  current="$(role)"; port="$(read_value "$REMOTE_PORT_FILE")"
  clear_host_firewall
  iptables -N "$INPUT_CHAIN"
  iptables -A "$INPUT_CHAIN" -i lo -j ACCEPT
  iptables -A "$INPUT_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  if [[ "$current" == exit && -n "$port" ]]; then
    iptables -A "$INPUT_CHAIN" -p udp --dport "$port" -j ACCEPT
  fi
  iptables -A "$INPUT_CHAIN" -j RETURN
  iptables -I INPUT 1 -j "$INPUT_CHAIN"
}

clear_host_firewall() {
  while iptables -C INPUT -j "$INPUT_CHAIN" 2>/dev/null; do iptables -D INPUT -j "$INPUT_CHAIN" 2>/dev/null || true; done
  iptables -F "$INPUT_CHAIN" 2>/dev/null || true
  iptables -X "$INPUT_CHAIN" 2>/dev/null || true
}

setup_mangle_chain() {
  local chain="$1" hook="$2"
  iptables -t mangle -N "$chain" 2>/dev/null || true
  iptables -t mangle -F "$chain"
  iptables -t mangle -C "$hook" -j "$chain" 2>/dev/null || iptables -t mangle -I "$hook" 1 -j "$chain"
}

clear_mangle_chains() {
  local chain hook
  for chain in "$MANGLE_OUT_CHAIN" "$MANGLE_PRE_CHAIN"; do
    for hook in OUTPUT PREROUTING; do
      while iptables -t mangle -C "$hook" -j "$chain" 2>/dev/null; do iptables -t mangle -D "$hook" -j "$chain" 2>/dev/null || true; done
    done
    iptables -t mangle -F "$chain" 2>/dev/null || true
    iptables -t mangle -X "$chain" 2>/dev/null || true
  done
}

clear_script_nyanpass_routing_rules() {
  while iptables -t mangle -C OUTPUT -j "$NYANPASS_OUT_CHAIN" 2>/dev/null; do iptables -t mangle -D OUTPUT -j "$NYANPASS_OUT_CHAIN" 2>/dev/null || true; done
  while iptables -t mangle -C PREROUTING -j "$NYANPASS_IN_CHAIN" 2>/dev/null; do iptables -t mangle -D PREROUTING -j "$NYANPASS_IN_CHAIN" 2>/dev/null || true; done
  iptables -t mangle -F "$NYANPASS_OUT_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$NYANPASS_OUT_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$NYANPASS_IN_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$NYANPASS_IN_CHAIN" 2>/dev/null || true
}

clear_entry_forward_rules() {
  local wan_if exit_ip port ssh_ports
  [[ "$(role)" == entry ]] || return 0
  wan_if="$(read_value "$WAN_IF_FILE")"; exit_ip="$(read_value "$PEER_ADDRESS_FILE")"; exit_ip="${exit_ip%%/*}"
  [[ -n "$wan_if" && -n "$exit_ip" ]] || return 0
  if [[ -f "$PORTS_FILE" ]]; then
    while read -r port; do
      valid_port "$port" || continue
      iptables -t nat -D PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
      iptables -t nat -D PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || true
      iptables -D FORWARD -i "$wan_if" -o "$WG_IF" -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -i "$WG_IF" -o "$wan_if" -p tcp --sport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -i "$wan_if" -o "$WG_IF" -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -i "$WG_IF" -o "$wan_if" -p udp --sport "$port" -j ACCEPT 2>/dev/null || true
    done < "$PORTS_FILE"
  fi
  ssh_ports="$(protected_ssh_ports_csv)"
  iptables -t nat -D PREROUTING -i "$wan_if" -p tcp -m multiport ! --dports "$ssh_ports" -j DNAT --to-destination "$exit_ip" 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$wan_if" -p udp -j DNAT --to-destination "$exit_ip" 2>/dev/null || true
  iptables -D FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
}

apply_entry_forward_rules() {
  local wan_if exit_ip port ssh_ports
  [[ "$(role)" == entry ]] || return 0
  wan_if="$(read_value "$WAN_IF_FILE")"; exit_ip="$(read_value "$PEER_ADDRESS_FILE")"; exit_ip="${exit_ip%%/*}"
  [[ -n "$wan_if" && -n "$exit_ip" ]] || return 0
  clear_entry_forward_rules
  if [[ "$(mode)" == global ]]; then
    ssh_ports="$(refresh_ssh_ports)"
    iptables -t nat -A PREROUTING -i "$wan_if" -p tcp -m multiport ! --dports "$ssh_ports" -j DNAT --to-destination "$exit_ip"
    iptables -t nat -A PREROUTING -i "$wan_if" -p udp -j DNAT --to-destination "$exit_ip"
    iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  elif [[ -f "$PORTS_FILE" ]]; then
    while read -r port; do
      valid_port "$port" || continue
      is_protected_ssh_port "$port" && continue
      iptables -t nat -A PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}"
      iptables -t nat -A PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}"
      iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -p tcp --sport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -p udp --dport "$port" -j ACCEPT
      iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -p udp --sport "$port" -j ACCEPT
    done < "$PORTS_FILE"
  fi
  iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE
}

clear_entry_runtime_rules() {
  clear_script_nyanpass_routing_rules
  clear_entry_forward_rules
  clear_mangle_chains
  while iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null; do iptables -t nat -D POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || break; done
  ip route flush table "$ROUTE_TABLE_ID" 2>/dev/null || true
  clear_fw_policy_rules
}

disable_tunnel_policy() {
  [[ "$(role)" == entry ]] || return 0
  clear_entry_runtime_rules
}

require_wg_interface() {
  if ! ip link show "$WG_IF" >/dev/null 2>&1; then
    err "WireGuard 接口 ${WG_IF} 未启动，已撤销隧道策略以避免流量黑洞"
    disable_tunnel_policy
    return 1
  fi
}

ensure_policy_route() {
  require_wg_interface
  ensure_wan_bind_policy_rule
  ensure_carrier_policy_rule
  if ! fw_policy_rule_exists; then
    ip rule add fwmark "$FW_MARK" table "$ROUTE_TABLE_ID"
    fw_policy_rule_exists || { err 'WireGuard 策略路由创建失败'; return 1; }
  fi
  ip route replace default dev "$WG_IF" table "$ROUTE_TABLE_ID"
  iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE
}

apply_routing_mode() {
  local wan_if remote_host remote_port remote_ip port ssh_ports current_mode
  [[ "$(role)" == entry ]] || return 0
  current_mode="$(mode)"
  [[ "$current_mode" != nyanpass ]] || { enable_nyanpass_mode; return; }
  require_wg_interface
  ensure_policy_route
  clear_script_nyanpass_routing_rules
  apply_entry_forward_rules
  clear_mangle_chains
  setup_mangle_chain "$MANGLE_OUT_CHAIN" OUTPUT
  setup_mangle_chain "$MANGLE_PRE_CHAIN" PREROUTING
  ssh_ports="$(refresh_ssh_ports)"
  wan_if="$(read_value "$WAN_IF_FILE")"; remote_host="$(read_value "$REMOTE_HOST_FILE")"; remote_port="$(read_value "$REMOTE_PORT_FILE")"

  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -o lo -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j CONNMARK --save-mark
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p tcp -m multiport --sports "$ssh_ports" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p tcp -m multiport --dports "$ssh_ports" -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p udp --dport 53 -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p tcp --dport 53 -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p udp --dport 853 -j RETURN
  iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p tcp --dport 853 -j RETURN
  while read -r remote_ip; do
    valid_ipv4 "$remote_ip" || continue
    iptables -t mangle -A "$MANGLE_OUT_CHAIN" -d "${remote_ip}/32" -p udp --dport "$remote_port" -j RETURN
  done < <(resolve_ipv4s "$remote_host")

  iptables -t mangle -A "$MANGLE_PRE_CHAIN" -j CONNMARK --restore-mark
  iptables -t mangle -A "$MANGLE_PRE_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN

  if [[ "$current_mode" == global ]]; then
    iptables -t mangle -A "$MANGLE_OUT_CHAIN" -j CONNMARK --restore-mark
    iptables -t mangle -A "$MANGLE_OUT_CHAIN" -m mark --mark "$LOCAL_CONN_MARK" -j RETURN
    iptables -t mangle -A "$MANGLE_OUT_CHAIN" -j MARK --set-mark "$FW_MARK"
    iptables -t mangle -A "$MANGLE_PRE_CHAIN" -i "$wan_if" -p tcp -m multiport --dports "$ssh_ports" -j CONNMARK --set-mark "$LOCAL_CONN_MARK"
    iptables -t mangle -A "$MANGLE_PRE_CHAIN" -i "$wan_if" -p tcp -m multiport --dports "$ssh_ports" -j RETURN
    iptables -t mangle -A "$MANGLE_PRE_CHAIN" -i "$wan_if" -j MARK --set-mark "$FW_MARK"
  elif [[ -f "$PORTS_FILE" ]]; then
    while read -r port; do
      valid_port "$port" || continue
      is_protected_ssh_port "$port" && continue
      iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p tcp --dport "$port" -j MARK --set-mark "$FW_MARK"
      iptables -t mangle -A "$MANGLE_OUT_CHAIN" -p udp --dport "$port" -j MARK --set-mark "$FW_MARK"
      iptables -t mangle -A "$MANGLE_PRE_CHAIN" -p tcp --dport "$port" -j MARK --set-mark "$FW_MARK"
      iptables -t mangle -A "$MANGLE_PRE_CHAIN" -p udp --dport "$port" -j MARK --set-mark "$FW_MARK"
    done < "$PORTS_FILE"
  fi
}

set_mode() {
  local requested="$1"
  [[ "$requested" == global || "$requested" == split ]] || return 1
  write_value "$MODE_FILE" "$requested"
  apply_routing_mode
  ok "已切换到 $([[ "$requested" == global ]] && printf '全局' || printf '分流')模式"
}

enable_global_mode() { set_mode global; }
enable_split_mode() { set_mode split; }

enable_nyanpass_mode() {
  local wan_if ssh_ports
  [[ "$(role)" == entry ]] || { err '当前机器不是入口服务器'; return 1; }
  require_wg_interface
  ensure_policy_route
  wan_if="$(read_value "$WAN_IF_FILE")"
  [[ -n "$wan_if" ]] || { err '入口公网网卡未配置'; return 1; }
  clear_entry_forward_rules
  clear_mangle_chains
  clear_script_nyanpass_routing_rules
  ssh_ports="$(refresh_ssh_ports)"
  iptables -t mangle -N "$NYANPASS_IN_CHAIN" 2>/dev/null || true
  iptables -t mangle -N "$NYANPASS_OUT_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$NYANPASS_IN_CHAIN"
  iptables -t mangle -F "$NYANPASS_OUT_CHAIN"
  iptables -t mangle -A "$NYANPASS_IN_CHAIN" -i "$wan_if" -m addrtype --dst-type LOCAL -j CONNMARK --set-mark "$LOCAL_CONN_MARK"
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -o lo -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j CONNMARK --save-mark
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p tcp -m multiport --sports "$ssh_ports" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p tcp -m multiport --dports "$ssh_ports" -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p udp --dport 53 -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p tcp --dport 53 -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p udp --dport 853 -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p tcp --dport 853 -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -j CONNMARK --restore-mark
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark "$LOCAL_CONN_MARK" -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark "$FW_MARK" -j RETURN
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m conntrack --ctstate NEW -j MARK --set-mark "$FW_MARK"
  iptables -t mangle -A "$NYANPASS_OUT_CHAIN" -m mark --mark "$FW_MARK" -j CONNMARK --save-mark
  iptables -t mangle -I "$NYANPASS_IN_CHAIN" 1 -j CONNMARK --restore-mark
  iptables -t mangle -I "$NYANPASS_IN_CHAIN" 2 -m mark --mark "$CARRIER_MARK" -j RETURN
  iptables -t mangle -I PREROUTING 1 -j "$NYANPASS_IN_CHAIN"
  iptables -t mangle -I OUTPUT 1 -j "$NYANPASS_OUT_CHAIN"
  write_value "$MODE_FILE" nyanpass
  warn '已建立连接不会自动迁移，请重启相关业务或等待连接重建。'
}

get_mode_label() {
  case "${1:-$(mode)}" in global) printf '全局模式\n';; split) printf '分流模式\n';; nyanpass) printf 'NyanPass 转发模式\n';; *) printf '未知模式\n';; esac
}

restart_wg_service() {
  local service="wg-quick@${WG_IF}.service"
  systemctl enable "$service" >/dev/null 2>&1 || true
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    systemctl restart "$service"
  else
    if ip link show "$WG_IF" >/dev/null 2>&1; then wg-quick down "$WG_IF" >/dev/null 2>&1 || ip link delete "$WG_IF" 2>/dev/null || true; fi
    systemctl start "$service"
  fi
}

socket_port_is_bound() {
  local protocol="$1" port="$2"
  valid_port "$port" || return 1
  if [[ "$protocol" == udp ]]; then ss -H -lun 2>/dev/null; else ss -H -ltn 2>/dev/null; fi | \
    awk -v p="$port" '{for(i=1;i<=NF;i++) if($i ~ (":" p "$")) found=1} END{exit(found?0:1)}'
}

start_wg() {
  local current port
  current="$(role)"
  [[ "$current" == entry || "$current" == exit ]] || { err '尚未配置入口或出口角色'; return 1; }
  [[ -f "$WG_MARKER" && -s "$WG_CONFIG" ]] || { err "${WG_CONFIG} 不属于本脚本或尚未生成，拒绝启动"; return 1; }
  print_block '正在启动 WireGuard'
  systemctl stop "$HEALTH_TIMER" "$HEALTH_SERVICE" "$ROUTING_SERVICE" 2>/dev/null || true
  ensure_ip_forward
  setup_host_firewall
  restart_wg_service || { [[ "$current" == entry ]] && disable_tunnel_policy; err 'WireGuard 服务启动失败'; return 1; }
  require_wg_interface
  if [[ "$current" == exit ]]; then
    port="$(read_value "$REMOTE_PORT_FILE")"
    socket_port_is_bound udp "$port" || { err "WireGuard UDP ${port} 未监听"; return 1; }
    setup_resilience || { err '出口自愈服务安装失败'; return 1; }
    print_ok '出口已启动'
    return 0
  fi
  apply_routing_mode || { disable_tunnel_policy; err '入口策略路由应用失败'; return 1; }
  setup_resilience || { disable_tunnel_policy; err '入口自愈服务安装失败'; return 1; }
  if entry_transport_healthy; then
    print_ok '入口已启动，端到端握手正常'
    return 0
  fi
  disable_tunnel_policy
  warn 'WireGuard 接口已启动，但尚未与出口完成握手；已暂时撤销隧道策略，健康检查会自动恢复。'
  return 1
}

stop_wg() {
  print_block '正在停止 WireGuard'
  systemctl stop "$HEALTH_TIMER" "$HEALTH_SERVICE" "$ROUTING_SERVICE" 2>/dev/null || true
  disable_tunnel_policy
  clear_host_firewall
  if [[ ! -f "$WG_MARKER" ]]; then
    warn "${WG_CONFIG} 没有本脚本管理标记，已保留现有 WireGuard 接口和服务"
    return 0
  fi
  systemctl stop "wg-quick@${WG_IF}.service" 2>/dev/null || true
  wg-quick down "$WG_IF" 2>/dev/null || true
  ip route flush table "$ROUTE_TABLE_ID" 2>/dev/null || true
  clear_fw_policy_rules; clear_carrier_policy_rule; clear_wan_bind_policy_rule
  print_ok '已停止'
}

restart_wg() { stop_wg; start_wg; }

install_manager_copy() {
  local source_path
  source_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
  [[ "$source_path" == "$MANAGER_BIN" ]] || install -m 0755 "$source_path" "$MANAGER_BIN"
}

setup_resilience() {
  install_manager_copy
  cat > "/etc/systemd/system/${ROUTING_SERVICE}" <<EOF
[Unit]
Description=Restore WireGuard policy routing
After=network-online.target wg-quick@${WG_IF}.service
Wants=network-online.target wg-quick@${WG_IF}.service

[Service]
Type=oneshot
ExecStart=${MANAGER_BIN} --restore-routing
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  cat > "/etc/systemd/system/${HEALTH_SERVICE}" <<EOF
[Unit]
Description=WireGuard end-to-end health check
After=network-online.target wg-quick@${WG_IF}.service ${ROUTING_SERVICE}
Wants=${ROUTING_SERVICE}

[Service]
Type=oneshot
ExecStart=${MANAGER_BIN} --healthcheck
TimeoutStartSec=120
EOF
  cat > "/etc/systemd/system/${HEALTH_TIMER}" <<EOF
[Unit]
Description=Run WireGuard health check every 30 seconds

[Timer]
OnBootSec=2min
OnUnitActiveSec=30s
AccuracySec=5s
RandomizedDelaySec=5s
Persistent=true
Unit=${HEALTH_SERVICE}

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable "$ROUTING_SERVICE" "$HEALTH_TIMER" >/dev/null 2>&1 || true
  systemctl restart "$ROUTING_SERVICE"
  systemctl restart "$HEALTH_TIMER"
}

latest_handshake_epoch() {
  wg show "$WG_IF" latest-handshakes 2>/dev/null | awk 'BEGIN{max=0} $2>max{max=$2} END{print max}' || true
}

exit_runtime_ready() {
  local wan_if peer_ip port
  [[ "$(role)" == exit ]] || return 1
  wan_if="$(read_value "$WAN_IF_FILE")"; peer_ip="$(read_value "$PEER_ADDRESS_FILE")"; peer_ip="${peer_ip%%/*}"
  port="$(read_value "$REMOTE_PORT_FILE")"
  ip link show "$WG_IF" >/dev/null 2>&1 || return 1
  socket_port_is_bound udp "$port" || return 1
  iptables -C INPUT -j "$INPUT_CHAIN" 2>/dev/null || return 1
  iptables -C FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || return 1
  iptables -C FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || return 1
  iptables -t nat -C POSTROUTING -s "${peer_ip}/32" -o "$wan_if" -j MASQUERADE 2>/dev/null || return 1
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
}

restore_exit_runtime() {
  local wan_if peer_ip
  [[ "$(role)" == exit ]] || return 0
  require_wg_interface
  wan_if="$(read_value "$WAN_IF_FILE")"; peer_ip="$(read_value "$PEER_ADDRESS_FILE")"; peer_ip="${peer_ip%%/*}"
  ensure_ip_forward; setup_host_firewall
  iptables -C FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$WG_IF" -o "$wan_if" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  iptables -C FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$wan_if" -o "$WG_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -t nat -C POSTROUTING -s "${peer_ip}/32" -o "$wan_if" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "${peer_ip}/32" -o "$wan_if" -j MASQUERADE
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}

restore_managed_runtime() {
  case "$(role)" in exit) restore_exit_runtime;; entry) restore_entry_routing;; *) return 0;; esac
}

exit_healthcheck() {
  [[ "$(role)" == exit ]] || return 0
  exit_runtime_ready && return 0
  logger -t wg-health 'exit runtime rules missing; restoring'
  if ! ip link show "$WG_IF" >/dev/null 2>&1; then
    systemctl restart "wg-quick@${WG_IF}.service" || return 1
  fi
  restore_exit_runtime
  exit_runtime_ready
}

managed_healthcheck() {
  case "$(role)" in exit) exit_healthcheck;; entry) entry_healthcheck;; *) return 0;; esac
}

entry_transport_healthy() {
  local now handshake age exit_ip
  ip link show "$WG_IF" >/dev/null 2>&1 || return 1
  now="$(date +%s)"; handshake="$(latest_handshake_epoch)"
  if [[ "$handshake" =~ ^[0-9]+$ ]] && ((handshake > 0)); then
    age=$((now - handshake)); ((age >= 0 && age <= HEALTH_HANDSHAKE_MAX_AGE)) && return 0
  fi
  exit_ip="$(read_value "$PEER_ADDRESS_FILE")"; exit_ip="${exit_ip%%/*}"
  if [[ -n "$exit_ip" ]] && command -v ping >/dev/null 2>&1; then
    ping -n -c 1 -W 3 "$exit_ip" >/dev/null 2>&1 || true
    handshake="$(latest_handshake_epoch)"; now="$(date +%s)"
    if [[ "$handshake" =~ ^[0-9]+$ ]] && ((handshake > 0)); then
      age=$((now - handshake)); ((age >= 0 && age <= HEALTH_HANDSHAKE_MAX_AGE)) && return 0
    fi
    return 1
  fi
  return 1
}

entry_routing_ready() {
  local current wan_if exit_ip ssh_ports port
  ip link show "$WG_IF" >/dev/null 2>&1 || return 1
  carrier_policy_rule_exists || return 1
  fw_policy_rule_exists || return 1
  wan_if="$(read_value "$WAN_IF_FILE")"; [[ -n "$wan_if" ]] && wan_bind_policy_rule_exists "$wan_if" || return 1
  ip route show table "$ROUTE_TABLE_ID" 2>/dev/null | grep -Eq "^default .*dev ${WG_IF}([[:space:]]|$)" || return 1
  iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || return 1
  current="$(mode)"; ssh_ports="$(protected_ssh_ports_csv)"; exit_ip="$(read_value "$PEER_ADDRESS_FILE")"; exit_ip="${exit_ip%%/*}"
  case "$current" in
    global|split)
      iptables -t mangle -C OUTPUT -j "$MANGLE_OUT_CHAIN" 2>/dev/null || return 1
      iptables -t mangle -C PREROUTING -j "$MANGLE_PRE_CHAIN" 2>/dev/null || return 1
      iptables -t mangle -C "$MANGLE_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j CONNMARK --save-mark 2>/dev/null || return 1
      iptables -t mangle -C "$MANGLE_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN 2>/dev/null || return 1
      iptables -t mangle -C "$MANGLE_PRE_CHAIN" -j CONNMARK --restore-mark 2>/dev/null || return 1
      iptables -t mangle -C "$MANGLE_PRE_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN 2>/dev/null || return 1
      for port in 53 853; do
        iptables -t mangle -C "$MANGLE_OUT_CHAIN" -p udp --dport "$port" -j RETURN 2>/dev/null || return 1
        iptables -t mangle -C "$MANGLE_OUT_CHAIN" -p tcp --dport "$port" -j RETURN 2>/dev/null || return 1
      done
      ;;
    nyanpass)
      iptables -t mangle -C OUTPUT -j "$NYANPASS_OUT_CHAIN" 2>/dev/null || return 1
      iptables -t mangle -C PREROUTING -j "$NYANPASS_IN_CHAIN" 2>/dev/null || return 1
      iptables -t mangle -C "$NYANPASS_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j CONNMARK --save-mark 2>/dev/null || return 1
      iptables -t mangle -C "$NYANPASS_OUT_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN 2>/dev/null || return 1
      iptables -t mangle -C "$NYANPASS_IN_CHAIN" -j CONNMARK --restore-mark 2>/dev/null || return 1
      iptables -t mangle -C "$NYANPASS_IN_CHAIN" -m mark --mark "$CARRIER_MARK" -j RETURN 2>/dev/null || return 1
      for port in 53 853; do
        iptables -t mangle -C "$NYANPASS_OUT_CHAIN" -p udp --dport "$port" -j RETURN 2>/dev/null || return 1
        iptables -t mangle -C "$NYANPASS_OUT_CHAIN" -p tcp --dport "$port" -j RETURN 2>/dev/null || return 1
      done
      return 0
      ;;
    *) return 1;;
  esac
  if [[ "$current" == global ]]; then
    iptables -t mangle -C "$MANGLE_OUT_CHAIN" -j MARK --set-mark "$FW_MARK" 2>/dev/null || return 1
    iptables -t nat -C PREROUTING -i "$wan_if" -p tcp -m multiport ! --dports "$ssh_ports" -j DNAT --to-destination "$exit_ip" 2>/dev/null || return 1
    iptables -t nat -C PREROUTING -i "$wan_if" -p udp -j DNAT --to-destination "$exit_ip" 2>/dev/null || return 1
  elif [[ -f "$PORTS_FILE" ]]; then
    while read -r port; do
      valid_port "$port" || continue; is_protected_ssh_port "$port" && continue
      iptables -t mangle -C "$MANGLE_OUT_CHAIN" -p tcp --dport "$port" -j MARK --set-mark "$FW_MARK" 2>/dev/null || return 1
      iptables -t mangle -C "$MANGLE_OUT_CHAIN" -p udp --dport "$port" -j MARK --set-mark "$FW_MARK" 2>/dev/null || return 1
      iptables -t nat -C PREROUTING -i "$wan_if" -p tcp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || return 1
      iptables -t nat -C PREROUTING -i "$wan_if" -p udp --dport "$port" -j DNAT --to-destination "${exit_ip}:${port}" 2>/dev/null || return 1
    done < "$PORTS_FILE"
  fi
}

restore_entry_routing() {
  [[ "$(role)" == entry ]] || return 0
  require_wg_interface
  setup_host_firewall
  apply_routing_mode
}

entry_healthcheck() {
  [[ "$(role)" == entry ]] || return 0
  local routing_ready=n failures=0 attempt handshake now age=999999
  entry_routing_ready && routing_ready=y
  handshake="$(latest_handshake_epoch)"; now="$(date +%s)"
  if [[ "$handshake" =~ ^[0-9]+$ ]] && ((handshake > 0)); then age=$((now - handshake)); fi
  if entry_transport_healthy; then
    if [[ "$routing_ready" != y ]]; then restore_entry_routing || { disable_tunnel_policy; return 1; }; fi
    printf '0\n' > "$HEALTH_FAILURE_FILE"
    return 0
  fi
  disable_tunnel_policy
  [[ -f "$HEALTH_FAILURE_FILE" ]] && failures="$(cat "$HEALTH_FAILURE_FILE" 2>/dev/null || printf 0)"
  [[ "$failures" =~ ^[0-9]+$ ]] || failures=0
  failures=$((failures + 1)); printf '%s\n' "$failures" > "$HEALTH_FAILURE_FILE"
  logger -t wg-health "failure ${failures}/${HEALTH_FAILURE_THRESHOLD}; handshake_age=${age}s"
  ((failures < HEALTH_FAILURE_THRESHOLD)) && return 0

  logger -t wg-health 'rotating resolved WireGuard endpoint'
  refresh_entry_endpoint y || true
  for attempt in 1 2 3 4; do
    sleep 5
    if entry_transport_healthy; then restore_entry_routing; printf '0\n' > "$HEALTH_FAILURE_FILE"; logger -t wg-health 'recovered after endpoint refresh'; return 0; fi
  done

  logger -t wg-health 'endpoint refresh failed; restarting WireGuard'
  if ! systemctl restart "wg-quick@${WG_IF}.service"; then disable_tunnel_policy; return 1; fi
  require_wg_interface || return 1
  for attempt in 1 2 3 4; do
    sleep 5
    if entry_transport_healthy; then restore_entry_routing; printf '0\n' > "$HEALTH_FAILURE_FILE"; logger -t wg-health 'recovered after WireGuard restart'; return 0; fi
  done
  disable_tunnel_policy
  printf '0\n' > "$HEALTH_FAILURE_FILE"
  logger -t wg-health 'recovery failed; tunnel policy remains removed'
  return 1
}

add_port() {
  local port="$1"
  valid_port "$port" || { err '端口无效'; return 1; }
  refresh_ssh_ports >/dev/null
  is_protected_ssh_port "$port" && { err "端口 ${port} 是 SSH 直连保护端口"; return 1; }
  ensure_dirs; touch "$PORTS_FILE"; chmod 600 "$PORTS_FILE"
  grep -qxF "$port" "$PORTS_FILE" || printf '%s\n' "$port" >> "$PORTS_FILE"
  apply_routing_mode
}

remove_port() {
  local port="$1" tmp
  valid_port "$port" || { err '端口无效'; return 1; }
  [[ -f "$PORTS_FILE" ]] || return 0
  tmp="$(mktemp)"
  awk -v p="$port" '$0!=p' "$PORTS_FILE" > "$tmp"
  install -m 600 "$tmp" "$PORTS_FILE"; rm -f "$tmp"
  apply_routing_mode
}

base64_encode() { base64 2>/dev/null | tr -d '\r\n'; }
base64_decode() { printf '%s' "$1" | base64 -d 2>/dev/null; }

export_exit_code() {
  local host port entry_addr exit_addr public payload
  host="$(read_value "$REMOTE_HOST_FILE")"; port="$(read_value "$REMOTE_PORT_FILE")"
  entry_addr="$(read_value "$PEER_ADDRESS_FILE")"; exit_addr="$(read_value "$WG_ADDRESS_FILE")"
  public="$(read_value "$WG_PUBLIC_KEY_FILE")"
  payload="${host}|${port}|${entry_addr}|${exit_addr}|${public}"
  printf 'WG1:%s\n' "$(printf '%s' "$payload" | base64_encode)"
}

import_exit_code() {
  local code="$1" payload host port entry_addr exit_addr public endpoint_ip
  [[ "$code" == WG1:* ]] || { err '连接码前缀无效，应为 WG1:'; return 1; }
  payload="$(base64_decode "${code#WG1:}")" || { err '连接码解码失败'; return 1; }
  IFS='|' read -r host port entry_addr exit_addr public <<< "$payload"
  valid_host "$host" && valid_port "$port" && valid_ipv4_cidr "$entry_addr" && \
    valid_ipv4_cidr "$exit_addr" && valid_wg_key "$public" || { err '连接码字段无效'; return 1; }
  [[ "${entry_addr%%/*}" != "${exit_addr%%/*}" ]] || { err '连接码中的入口和出口 WG 地址不能相同'; return 1; }
  endpoint_ip="$(select_endpoint_ipv4 "$host")" || { err "无法解析出口地址 ${host}"; return 1; }
  write_value "$REMOTE_HOST_FILE" "$host"; write_value "$REMOTE_PORT_FILE" "$port"
  write_value "$WG_ADDRESS_FILE" "$entry_addr"; write_value "$PEER_ADDRESS_FILE" "$exit_addr"
  write_value "$PEER_PUBLIC_KEY_FILE" "$public"; write_value "$ENDPOINT_IP_FILE" "$endpoint_ip"
  write_value "$WAN_IF_FILE" "$(get_wan_if)"
  ok '已导入出口连接码'
}

configure_exit() {
  local host port address entry_address wan_if input_wan_if public entry_public
  set_role exit; ensure_dirs
  print_block '配置 WireGuard 出口服务器'
  install_packages
  print_block '配置出口 WireGuard 身份'
  echo '可粘贴自定义私钥；回车将自动生成或复用现有私钥。'
  ensure_local_wg_identity '出口服务器'
  public="$(read_value "$WG_PUBLIC_KEY_FILE")"
  print_block '出口 WireGuard 公钥'
  printf '%s\n' "$public"
  read -rp '入口服务器 WireGuard 公钥（首次可回车稍后填写）: ' entry_public
  if [[ -n "$entry_public" ]]; then
    valid_wg_key "$entry_public" || { err '入口 WireGuard 公钥格式无效'; return 1; }
    write_value "$PEER_PUBLIC_KEY_FILE" "$entry_public"
  elif [[ ! -s "$PEER_PUBLIC_KEY_FILE" ]]; then
    rm -f "$PEER_PUBLIC_KEY_FILE"
  fi
  while true; do
    read -rp '出口公网 IP / 域名: ' host; host="$(normalize_host "$host")"
    valid_host "$host" && break; print_err '出口地址无效'
  done
  read -rp "WireGuard UDP 监听端口 (默认 ${DEFAULT_WG_PORT}): " port; port="${port:-$DEFAULT_WG_PORT}"
  valid_port "$port" || { err '端口无效'; return 1; }
  read -rp "出口 WireGuard 内网地址 (默认 ${DEFAULT_EXIT_ADDRESS}): " address; address="${address:-$DEFAULT_EXIT_ADDRESS}"
  read -rp '入口 WireGuard 内网地址 (默认 10.0.0.2/32): ' entry_address; entry_address="${entry_address:-10.0.0.2/32}"
  valid_ipv4_cidr "$address" && valid_ipv4_cidr "$entry_address" || { err 'WireGuard 内网地址无效'; return 1; }
  [[ "${address%%/*}" != "${entry_address%%/*}" ]] || { err '入口和出口 WG 地址不能相同'; return 1; }
  wan_if="$(get_wan_if)"
  read -rp "出口公网网卡 (默认 ${wan_if}): " input_wan_if
  wan_if="${input_wan_if:-$wan_if}"
  [[ "$wan_if" =~ ^[A-Za-z0-9_.:-]+$ ]] || { err '网卡名无效'; return 1; }
  write_value "$REMOTE_HOST_FILE" "$host"; write_value "$REMOTE_PORT_FILE" "$port"
  write_value "$WG_ADDRESS_FILE" "$address"; write_value "$PEER_ADDRESS_FILE" "$entry_address"
  write_value "$WAN_IF_FILE" "$wan_if"
  ensure_ip_forward; write_exit_wg_config; start_wg
  print_block '出口配置完成'
  printf '出口地址: %s:%s\n出口 WG 地址: %s\n出口公钥: %s\n\n连接码：\n' "$host" "$port" "$address" "$public"
  export_exit_code
  [[ -s "$PEER_PUBLIC_KEY_FILE" ]] || print_warn '下一步在入口导入连接码，再回到出口菜单 11 → 3 填入入口公钥。'
}

configure_entry() {
  local code host port address exit_address endpoint_ip public default_if
  set_role entry; ensure_dirs
  print_block '配置 WireGuard 入口服务器'
  install_packages
  print_block '配置入口 WireGuard 身份'
  echo '可粘贴自定义私钥；回车将自动生成或复用现有私钥。'
  ensure_local_wg_identity '入口服务器'
  public="$(read_value "$WG_PUBLIC_KEY_FILE")"
  print_block '入口 WireGuard 公钥（需要填到出口机）'
  printf '%s\n' "$public"
  read -rp '粘贴出口连接码（没有则回车手动填写）: ' code
  if [[ -n "$code" ]]; then
    import_exit_code "$code"
  else
    prompt_wg_key '出口服务器' "$PEER_PUBLIC_KEY_FILE"
    read -rp '出口公网 IP / 域名: ' host; host="$(normalize_host "$host")"
    read -rp "出口 WireGuard UDP 端口 (默认 ${DEFAULT_WG_PORT}): " port; port="${port:-$DEFAULT_WG_PORT}"
    read -rp "入口 WireGuard 内网地址 (默认 ${DEFAULT_ENTRY_ADDRESS}): " address; address="${address:-$DEFAULT_ENTRY_ADDRESS}"
    read -rp '出口 WireGuard 内网地址 (默认 10.0.0.1/32): ' exit_address; exit_address="${exit_address:-10.0.0.1/32}"
    valid_host "$host" && valid_port "$port" && valid_ipv4_cidr "$address" && valid_ipv4_cidr "$exit_address" || { err '入口参数无效'; return 1; }
    [[ "${address%%/*}" != "${exit_address%%/*}" ]] || { err '入口和出口 WG 地址不能相同'; return 1; }
    endpoint_ip="$(select_endpoint_ipv4 "$host")" || { err "无法解析出口地址 ${host}"; return 1; }
    write_value "$REMOTE_HOST_FILE" "$host"; write_value "$REMOTE_PORT_FILE" "$port"
    write_value "$WG_ADDRESS_FILE" "$address"; write_value "$PEER_ADDRESS_FILE" "$exit_address"
    write_value "$ENDPOINT_IP_FILE" "$endpoint_ip"
  fi
  default_if="$(get_wan_if)"
  write_value "$WAN_IF_FILE" "$default_if"; set_mode_flag split
  write_entry_wg_config
  start_wg || true
  print_block '入口配置完成'
  printf '出口地址: %s:%s（当前解析 %s）\n入口 WG 地址: %s\n入口公钥: %s\n' \
    "$(read_value "$REMOTE_HOST_FILE")" "$(read_value "$REMOTE_PORT_FILE")" "$(read_value "$ENDPOINT_IP_FILE")" \
    "$(read_value "$WG_ADDRESS_FILE")" "$public"
  if entry_transport_healthy; then
    restore_entry_routing
    print_ok '端到端握手正常'
  else
    print_warn '出口尚未配置此入口公钥，或 UDP 端口不可达；策略已保持直连等待自愈。'
  fi
}

update_entry_endpoint() {
  local host port endpoint_ip
  [[ "$(role)" == entry ]] || { err '当前不是入口服务器'; return 1; }
  read -rp "新出口 IP / 域名 (默认 $(read_value "$REMOTE_HOST_FILE")): " host
  host="$(normalize_host "${host:-$(read_value "$REMOTE_HOST_FILE")}")"
  read -rp "新出口 UDP 端口 (默认 $(read_value "$REMOTE_PORT_FILE")): " port
  port="${port:-$(read_value "$REMOTE_PORT_FILE")}"
  valid_host "$host" && valid_port "$port" || { err '出口地址或端口无效'; return 1; }
  endpoint_ip="$(select_endpoint_ipv4 "$host")" || { err "无法解析出口地址 ${host}"; return 1; }
  write_value "$REMOTE_HOST_FILE" "$host"; write_value "$REMOTE_PORT_FILE" "$port"; write_value "$ENDPOINT_IP_FILE" "$endpoint_ip"
  write_entry_wg_config; start_wg
}

update_exit_peer() {
  [[ "$(role)" == exit ]] || { err '当前不是出口服务器'; return 1; }
  prompt_wg_key '新的入口服务器' "$PEER_PUBLIC_KEY_FILE"
  write_exit_wg_config; start_wg
}

show_health_summary() {
  local current handshake now age port
  current="$(role)"; handshake="$(latest_handshake_epoch)"; now="$(date +%s)"
  if ip link show "$WG_IF" >/dev/null 2>&1; then printf '  ✅ WireGuard 接口: active\n'; else printf '  ❌ WireGuard 接口: missing\n'; fi
  if [[ "$current" == exit ]]; then
    port="$(read_value "$REMOTE_PORT_FILE")"
    if socket_port_is_bound udp "$port"; then printf '  ✅ UDP %s: 正在监听\n' "$port"; else printf '  ❌ UDP %s: 未监听\n' "${port:-未配置}"; fi
    if exit_runtime_ready; then printf '  ✅ 出口转发/NAT 规则: 完整\n'; else printf '  ❌ 出口转发/NAT 规则: 缺失\n'; fi
    if systemctl is-active --quiet "$HEALTH_TIMER" 2>/dev/null; then printf '  ✅ 30 秒规则自愈定时器: active\n'; else printf '  ❌ 30 秒规则自愈定时器: inactive\n'; fi
  else
    if entry_routing_ready; then printf '  ✅ 策略路由和防火墙规则: 完整\n'; else printf '  ⚠️  策略路由: 未启用或不完整\n'; fi
    if systemctl is-active --quiet "$HEALTH_TIMER" 2>/dev/null; then printf '  ✅ 30 秒自愈定时器: active\n'; else printf '  ❌ 30 秒自愈定时器: inactive\n'; fi
    printf '  健康检查连续失败: %s/%s\n' "$(cat "$HEALTH_FAILURE_FILE" 2>/dev/null || printf 0)" "$HEALTH_FAILURE_THRESHOLD"
  fi
  if [[ "$handshake" =~ ^[0-9]+$ ]] && ((handshake > 0)); then
    age=$((now - handshake))
    if ((age <= HEALTH_HANDSHAKE_MAX_AGE)); then printf '  ✅ 最近握手: %s 秒前\n' "$age"; else printf '  ⚠️  最近握手: %s 秒前\n' "$age"; fi
  else
    printf '  ❌ 尚无有效握手\n'
  fi
}

show_status() {
  print_block 'WireGuard 链路状态'
  printf '角色: %s\n模式: %s\n' "$(role)" "$(get_mode_label)"
  [[ -s "$REMOTE_HOST_FILE" ]] && printf '出口地址: %s:%s\n' "$(read_value "$REMOTE_HOST_FILE")" "$(read_value "$REMOTE_PORT_FILE")"
  [[ "$(role)" == entry && -s "$ENDPOINT_IP_FILE" ]] && printf '当前端点 IPv4: %s\n' "$(read_value "$ENDPOINT_IP_FILE")"
  [[ -s "$WG_ADDRESS_FILE" ]] && printf '本机 WG 地址: %s\n' "$(read_value "$WG_ADDRESS_FILE")"
  [[ -s "$WG_PUBLIC_KEY_FILE" ]] && printf '本机 WG 公钥: %s\n' "$(read_value "$WG_PUBLIC_KEY_FILE")"
  [[ "$(role)" == entry ]] && printf 'SSH 直连保护端口: %s\n' "$(protected_ssh_ports_csv)"
  printf '\n健康检查:\n'; show_health_summary
  printf '\n'; wg show "$WG_IF" 2>/dev/null || true
}

start_all() { [[ -s "$ROLE_FILE" ]] || { err '尚未配置角色'; return 1; }; start_wg; }
stop_all() { stop_wg; }

uninstall_all() {
  local answer owned=n
  print_block '卸载 WireGuard 组网'
  read -rp '确认删除本脚本创建的配置和服务？[y/N]: ' answer
  [[ "$answer" =~ ^[Yy]$ ]] || { info '已取消'; return 0; }
  [[ -f "$WG_MARKER" ]] && owned=y
  set +e
  stop_wg
  systemctl stop "$HEALTH_TIMER" "$HEALTH_SERVICE" "$ROUTING_SERVICE" 2>/dev/null
  systemctl disable "$HEALTH_TIMER" "$ROUTING_SERVICE" 2>/dev/null
  if [[ "$owned" == y ]]; then
    systemctl stop "wg-quick@${WG_IF}.service" 2>/dev/null
    systemctl disable "wg-quick@${WG_IF}.service" 2>/dev/null
  fi
  rm -f "/etc/systemd/system/${HEALTH_SERVICE}" "/etc/systemd/system/${HEALTH_TIMER}" "/etc/systemd/system/${ROUTING_SERVICE}" "$MANAGER_BIN" "$HEALTH_FAILURE_FILE"
  systemctl daemon-reload
  if [[ "$owned" == y ]]; then rm -f "$WG_CONFIG" "$WG_MARKER"; elif [[ -e "$WG_CONFIG" ]]; then warn "${WG_CONFIG} 不属于本脚本，已保留"; fi
  rm -rf "$BASE_DIR"
  if [[ -f /etc/sysctl.conf ]]; then sed -i "/# ${APP_NAME}/,+1d" /etc/sysctl.conf 2>/dev/null; sysctl -p >/dev/null 2>&1; fi
  set -e
  ok '已卸载本脚本创建的 WireGuard 配置、定时器和路由规则'
}

manage_entry_ports() {
  [[ "$(role)" == entry ]] || { err '当前不是入口服务器'; return 1; }
  local choice port
  while true; do
    print_block '入口端口分流管理'
    echo '1) 查看当前分流端口'
    echo '2) 添加分流端口'
    echo '3) 删除分流端口'
    echo '0) 返回'
    read -rp '请选择: ' choice
    case "$choice" in
      1) [[ -s "$PORTS_FILE" ]] && cat "$PORTS_FILE" || print_warn '当前没有分流端口';;
      2) read -rp '端口: ' port; add_port "$port" && print_ok "已添加端口 ${port}";;
      3) read -rp '端口: ' port; remove_port "$port" && print_ok "已删除端口 ${port}";;
      0) return 0;;
      *) print_err '无效选择';;
    esac
  done
}

manage_entry_mode() {
  [[ "$(role)" == entry ]] || { err '当前不是入口服务器'; return 1; }
  local choice
  while true; do
    print_block '入口模式管理'
    printf '当前模式: %s\n' "$(get_mode_label)"
    echo '1) 全局模式'
    echo '2) 分流模式'
    echo '3) NyanPass 转发模式'
    echo '0) 返回'
    read -rp '请选择: ' choice
    case "$choice" in
      1) enable_global_mode;; 2) enable_split_mode;; 3) enable_nyanpass_mode;; 0) return 0;; *) print_err '无效选择';;
    esac
  done
}

manage_exit_node() {
  [[ "$(role)" == exit ]] || { err '当前不是出口服务器'; return 1; }
  local choice port
  while true; do
    print_block '出口高级管理'
    echo '1) 查看状态和连接码'
    echo '2) 修改 WG UDP 监听端口'
    echo '3) 更新入口公钥'
    echo '0) 返回'
    read -rp '请选择: ' choice
    case "$choice" in
      1) show_status; printf '\n连接码：\n'; export_exit_code;;
      2)
        read -rp '新 WireGuard UDP 端口: ' port
        valid_port "$port" || { print_err '端口无效'; continue; }
        write_value "$REMOTE_PORT_FILE" "$port"; write_exit_wg_config; start_wg
        print_ok '出口监听端口已更新，请同步入口';;
      3) update_exit_peer;;
      0) return 0;;
      *) print_err '无效选择';;
    esac
  done
}

menu() {
  local choice
  while true; do
    echo
    echo '================ 🛡️ WireGuard 一键脚本 ================'
    echo '1) 配置为 出口服务器'
    echo '2) 配置为 入口服务器'
    echo '3) 查看链路状态'
    echo '4) 启动'
    echo '5) 停止'
    echo '6) 重启'
    echo '7) 卸载并清理'
    echo '8) 管理入口端口分流'
    echo '9) 管理入口模式'
    echo '10) 修改出口 IP / 域名（仅入口）'
    echo '11) 出口高级管理'
    echo '0) 退出'
    echo '======================================================'
    read -rp '请选择: ' choice
    case "$choice" in
      1) configure_exit;; 2) configure_entry;; 3) show_status;; 4) start_wg;; 5) stop_wg;; 6) restart_wg;;
      7) uninstall_all;; 8) manage_entry_ports;; 9) manage_entry_mode;; 10) update_entry_endpoint;; 11) manage_exit_node;;
      0) return 0;; *) print_err '无效选择';;
    esac
  done
}

usage() {
  cat <<EOF
用法：sudo bash $0 [选项]

不带选项进入交互菜单。
  --entry       配置入口机
  --exit        配置出口机
  --status      查看状态
  --start       启动服务
  --stop        停止服务
  --restart     重启服务
  --restore-routing  恢复当前角色运行规则（供 systemd 调用）
  --healthcheck      执行当前角色健康检查（供 systemd 调用）
  --uninstall   卸载本脚本内容
  --help        显示帮助
EOF
}

main() {
  case "${1:-}" in
    --entry) configure_entry;; --exit) configure_exit;; --status) show_status;; --start) start_all;; --stop) stop_all;;
    --restart) restart_wg;; --restore-routing) restore_managed_runtime;; --healthcheck) managed_healthcheck;;
    --uninstall) uninstall_all;; --help|-h) usage;; '') menu;; *) usage; return 1;;
  esac
}

main "$@"
