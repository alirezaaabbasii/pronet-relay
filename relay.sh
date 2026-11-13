#!/usr/bin/env bash
# =====================================================================
#  Pronet Relay — VLESS + TCP + TLS (Hetzner rDNS cert) behind a relay
#
#  Path:  user --443--> ENTRY (HAProxy) --8447 + PROXY v2--> EXIT (PasarGuard node)
#
#  Usage (menu):            bash relay.sh
#  Usage (direct):
#     EXIT  server:         bash relay.sh exit  ENTRY_IP[,ENTRY_IP2] EMAIL
#     ENTRY server:         bash relay.sh entry EXIT_PUBLIC_IP [EXIT_PRIVATE_IP]
#     EXIT  show cert:      bash relay.sh cert
#     EXIT  add entry IP:   bash relay.sh add-entry IP
#     ENTRY add exit:       bash relay.sh add-exit EXIT_PUBLIC_IP [EXIT_PRIVATE_IP]
#     Status (any):         bash relay.sh status
# =====================================================================
set -euo pipefail

RAW_URL="https://raw.githubusercontent.com/alirezaaabbasii/pronet-relay/main/relay.sh"
PORT=8447                       # inbound port on EXIT (must match PasarGuard inbound)
STATE=/etc/pronet-relay
FW_SCRIPT=/usr/local/sbin/pronet-relay-fw.sh
FW_UNIT=/etc/systemd/system/pronet-relay-fw.service
ACME=~/.acme.sh/acme.sh

c_cyan=$'\033[1;36m'; c_red=$'\033[1;31m'; c_grn=$'\033[1;32m'; c_ylw=$'\033[1;33m'; c_off=$'\033[0m'
say(){  echo -e "\n${c_cyan}==> $*${c_off}"; }
ok(){   echo -e "${c_grn}✔ $*${c_off}"; }
warn(){ echo -e "${c_ylw}! $*${c_off}"; }
die(){  echo -e "${c_red}ERROR: $*${c_off}"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root"
mkdir -p "$STATE"

valid_ip(){ [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
hz_host(){ local a b c d; IFS=. read -r a b c d <<<"$1"; echo "static.$d.$c.$b.$a.clients.your-server.de"; }
my_ip(){ ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}'; }
ask(){ local v; read -rp "$1: " v; echo "$v"; }

enable_bbr(){
  grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf || \
    printf "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
}

# ------------------------------------------------------------- EXIT ---
node_container(){
  local cnt
  cnt=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -iE 'pasarguard|pg-node|node' | awk 'NR==1{print $1}' || true)
  [[ -n "$cnt" ]] || die "PasarGuard node container not found. Install the node and connect it to the panel first."
  echo "$cnt"
}

node_dir(){
  local mnt
  mnt=$(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' "$1" | grep -E '^/var/lib' | head -1 || true)
  [[ -n "$mnt" ]] || mnt=/var/lib/pg-node
  echo "$mnt"
}

write_firewall(){
  local list="$STATE/entries.list"
  [[ -s "$list" ]] || die "No entry IPs saved"
  {
    echo '#!/bin/sh'
    echo 'iptables -N PRONET 2>/dev/null || true'
    echo 'iptables -F PRONET'
    while read -r ip; do [[ -n "$ip" ]] && echo "iptables -A PRONET -s $ip -j ACCEPT"; done <"$list"
    echo 'iptables -A PRONET -j DROP'
    echo "iptables -D INPUT -p tcp --dport $PORT -j PRONET 2>/dev/null || true"
    echo "iptables -I INPUT -p tcp --dport $PORT -j PRONET"
  } >"$FW_SCRIPT"
  chmod +x "$FW_SCRIPT"
  cat >"$FW_UNIT" <<EOF
[Unit]
Description=Pronet relay: allow port $PORT only from entry servers
After=network-online.target docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$FW_SCRIPT
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable pronet-relay-fw.service >/dev/null 2>&1
  systemctl restart pronet-relay-fw.service
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp >/dev/null
    while read -r ip; do [[ -n "$ip" ]] && ufw allow from "$ip" to any port "$PORT" proto tcp >/dev/null; done <"$list"
  fi
  ok "Port $PORT open only for: $(paste -sd, "$list")"
}

add_entries(){   # $1 = comma separated IPs
  local ip
  for ip in ${1//,/ }; do
    valid_ip "$ip" || die "Invalid IP: $ip"
    grep -qx "$ip" "$STATE/entries.list" 2>/dev/null || echo "$ip" >>"$STATE/entries.list"
  done
}

print_cert(){
  local host dir exp
  host=$(cat "$STATE/exit_host" 2>/dev/null) || die "Exit not set up on this server"
  dir=$(cat "$STATE/node_dir")
  exp=$(openssl x509 -enddate -noout -in "$dir/certs/hz.crt" | cut -d= -f2)
  echo -e "\n${c_ylw}Certificate for $host — expires: $exp${c_off}"
  echo "########## CERTIFICATE (copy from BEGIN to last END) ##########"
  cat "$dir/certs/hz.crt"
  echo "########## KEY ##########"
  cat "$dir/certs/hz.key"
  echo "##########################"
}

setup_exit(){
  local entries="${1:-}" email="${2:-}" ip host res cnt dir hook=()
  [[ -n "$entries" ]] || entries=$(ask "ENTRY server IP (several: comma separated)")
  [[ -n "$email"   ]] || email=$(ask "Email for the certificate")
  [[ -n "$entries" && -n "$email" ]] || die "Entry IP and email are required"

  say "Checking this server"
  ip=$(my_ip); host=$(hz_host "$ip")
  res=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}' || true)
  echo "IP:   $ip"; echo "HOST: $host -> ${res:-not resolved}"
  [[ "$res" == "$ip" ]] || die "Hostname does not resolve to this server (Hetzner IP with default rDNS required)"
  command -v docker >/dev/null || die "Docker not found — install PasarGuard node first"
  cnt=$(node_container); dir=$(node_dir "$cnt")
  echo "Node container: $cnt   data dir: $dir"
  mkdir -p "$dir/certs"
  echo "$host" >"$STATE/exit_host"; echo "$dir" >"$STATE/node_dir"; echo "$cnt" >"$STATE/node_cnt"

  if ss -ltnp "sport = :80" | grep -q LISTEN; then
    if ss -ltnp "sport = :80" | grep -q '"xray"'; then
      warn "Port 80 is used by the node's Xray — node is stopped ~30s during issue/renew"
      hook=(--pre-hook "docker stop $cnt" --post-hook "docker start $cnt")
    else
      die "Port 80 busy by another program: $(ss -ltnp 'sport = :80' | tail -1)"
    fi
  fi

  say "Installing acme.sh"
  apt-get update -qq && apt-get install -y -qq socat curl cron openssl >/dev/null
  [[ -x $ACME ]] || curl -s https://get.acme.sh | sh -s email="$email" >/dev/null

  say "Certificate for $host"
  if $ACME --list | grep -q "$host"; then
    ok "Certificate already exists — skipping issuance"
  elif ! $ACME --issue --standalone -d "$host" --keylength ec-256 --server letsencrypt "${hook[@]}"; then
    warn "Let's Encrypt failed — trying ZeroSSL"
    $ACME --register-account -m "$email" --server zerossl >/dev/null
    $ACME --issue --standalone -d "$host" --keylength ec-256 --server zerossl "${hook[@]}" || { docker start "$cnt" >/dev/null 2>&1 || true; die "Certificate issuance failed"; }
  fi
  docker start "$cnt" >/dev/null 2>&1 || true
  $ACME --install-cert -d "$host" --ecc \
    --key-file "$dir/certs/hz.key" --fullchain-file "$dir/certs/hz.crt" \
    --reloadcmd "docker restart $cnt" >/dev/null
  ok "Certificate installed"

  say "Firewall"
  add_entries "$entries"
  write_firewall

  say "BBR"; enable_bbr; ok "done"

  print_cert
  cat <<EOF

${c_grn}=================== EXIT DONE ===================${c_off}
EXIT_HOST = $host   (IP: $ip)

Now on the ENTRY server run:

   ${c_grn}bash <(curl -fsSL $RAW_URL) entry $ip${c_off}
=================================================
EOF
}

# ------------------------------------------------------------ ENTRY ---
write_haproxy(){
  local list="$STATE/exits.list" n=0 host ip conn
  [[ -s "$list" ]] || die "No exits saved"
  {
    cat <<EOF
global
    log /dev/log local0
    maxconn 60000
defaults
    mode tcp
    log global
    option tcpka
    timeout connect 5s
    timeout client  2h
    timeout server  2h
frontend in443
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
EOF
    while read -r host ip conn; do n=$((n+1)); echo "    use_backend exit$n if { req_ssl_sni -i $host }"; done <"$list"
    echo "    default_backend exit1"
    n=0
    while read -r host ip conn; do
      n=$((n+1))
      printf 'backend exit%s\n    server s%s %s:%s send-proxy-v2\n' "$n" "$n" "$conn" "$PORT"
    done <"$list"
  } >/etc/haproxy/haproxy.cfg.new
  haproxy -c -f /etc/haproxy/haproxy.cfg.new >/dev/null || die "HAProxy config invalid"
  [[ -f /etc/haproxy/haproxy.cfg ]] && cp /etc/haproxy/haproxy.cfg "$STATE/haproxy.cfg.bak"
  mv /etc/haproxy/haproxy.cfg.new /etc/haproxy/haproxy.cfg
  systemctl enable haproxy >/dev/null 2>&1
  systemctl restart haproxy
}

test_exits(){
  local host ip conn
  sleep 1
  while read -r host ip conn; do
    if timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$host" </dev/null 2>/dev/null \
         | openssl x509 -noout -subject 2>/dev/null | grep -q "$host"; then
      ok "$host ($ip) — relay OK"
    else
      warn "$host ($ip) — NO certificate (inbound not listening on $PORT yet, or this entry IP not allowed on exit)"
    fi
  done <"$STATE/exits.list"
}

add_exit(){   # $1 public IP, $2 optional private IP
  local pub="${1:-}" priv="${2:-}" host
  [[ -n "$pub" ]] || pub=$(ask "EXIT server PUBLIC IP")
  valid_ip "$pub" || die "Invalid IP: $pub"
  [[ -z "$priv" ]] || valid_ip "$priv" || die "Invalid private IP: $priv"
  host=$(hz_host "$pub")
  touch "$STATE/exits.list"
  if grep -q "^$host " "$STATE/exits.list"; then
    sed -i "\|^$host |d" "$STATE/exits.list"
  fi
  echo "$host $pub ${priv:-$pub}" >>"$STATE/exits.list"
}

setup_entry(){
  local pub="${1:-}" priv="${2:-}" ip host
  ip=$(my_ip); host=$(hz_host "$ip")
  if ss -ltnp "sport = :443" | grep -q LISTEN && ! ss -ltnp "sport = :443" | grep -q haproxy; then
    die "Port 443 is busy by another program: $(ss -ltnp 'sport = :443' | tail -1)"
  fi
  say "Installing HAProxy"
  apt-get update -qq && apt-get install -y -qq haproxy openssl >/dev/null
  add_exit "$pub" "$priv"
  say "Writing HAProxy config"; write_haproxy; ok "HAProxy running"
  say "BBR"; enable_bbr; ok "done"
  say "Testing relay to exits"; test_exits
  print_hosts
}

print_hosts(){
  local ip host ehost eip conn
  ip=$(my_ip); host=$(hz_host "$ip")
  echo -e "\n${c_grn}=================== ENTRY DONE ===================${c_off}"
  echo "ENTRY_HOST = $host   (IP: $ip)"
  while read -r ehost eip conn; do echo "  exit $eip  ->  SNI = $ehost"; done <"$STATE/exits.list"
  echo "=================================================="
}

# ----------------------------------------------------------- STATUS ---
status(){
  if [[ -f "$STATE/exit_host" ]]; then
    say "EXIT status"
    echo "Host: $(cat "$STATE/exit_host")"
    ss -tlnp | grep -q ":$PORT " && ok "Listening on $PORT" || warn "Nothing listening on $PORT"
    echo "Cert expires: $(openssl x509 -enddate -noout -in "$(cat "$STATE/node_dir")/certs/hz.crt" | cut -d= -f2)"
    echo "Allowed entries: $(paste -sd, "$STATE/entries.list")"
  fi
  if [[ -f "$STATE/exits.list" ]]; then
    say "ENTRY status"
    systemctl is-active --quiet haproxy && ok "HAProxy running" || warn "HAProxy NOT running"
    test_exits
  fi
  [[ -f "$STATE/exit_host" || -f "$STATE/exits.list" ]] || warn "Nothing set up on this server yet"
}

# ------------------------------------------------------------- MAIN ---
menu(){
  echo -e "${c_cyan}
  Pronet Relay
  ------------
  1) Setup EXIT   (this server is a PasarGuard node)
  2) Setup ENTRY  (relay server, not a node)
  3) EXIT : show certificate again (after renewal)
  4) EXIT : allow another entry IP
  5) ENTRY: add another exit
  6) Status / test
  0) Quit${c_off}"
  case "$(ask 'Choose')" in
    1) setup_exit ;;
    2) setup_entry ;;
    3) print_cert ;;
    4) add_entries "$(ask 'New entry IP')"; write_firewall ;;
    5) add_exit; write_haproxy; test_exits; print_hosts ;;
    6) status ;;
    *) exit 0 ;;
  esac
}

case "${1:-}" in
  exit)      setup_exit "${2:-}" "${3:-}" ;;
  entry)     setup_entry "${2:-}" "${3:-}" ;;
  cert)      print_cert ;;
  add-entry) add_entries "${2:-$(ask 'New entry IP')}"; write_firewall ;;
  add-exit)  add_exit "${2:-}" "${3:-}"; write_haproxy; test_exits; print_hosts ;;
  status)    status ;;
  "")        menu ;;
  *)         die "Unknown command: $1" ;;
esac
