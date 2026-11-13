#!/usr/bin/env bash
# =====================================================================
#  Pronet Relay — VLESS + TCP + TLS (Hetzner rDNS cert) behind a relay
#
#  user --443--> ENTRY (HAProxy, Hetzner) --8447 + PROXY v2--> EXIT (PasarGuard node)
#
#  Mode A: EXIT is Hetzner  -> certificate on EXIT, SNI = exit hostname
#          (one entry can serve many Hetzner exits, routed by SNI)
#  Mode B: EXIT is anywhere (Turkey, ...) -> certificate on ENTRY, SNI = entry hostname
#          (one entry serves one non-Hetzner exit)
#
#  Run:  bash <(curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-relay/main/relay.sh)
#
#  Direct commands:
#    exit      ENTRY_IP[,IP2] EMAIL   EXIT, Hetzner (mode A)
#    exit-ext  ENTRY_IP[,IP2] EMAIL   EXIT, other datacenter (mode B)
#    entry     EXIT_IP [EXIT_PRIV]    ENTRY for a Hetzner exit (mode A)
#    entry-ext EXIT_IP EMAIL          ENTRY for a non-Hetzner exit (mode B)
#    cert                             print certificate + key again
#    add-entry IP                     EXIT: allow another entry IP
#    status                           status / test
# =====================================================================
set -euo pipefail

RAW_URL="https://raw.githubusercontent.com/alirezaaabbasii/pronet-relay/main/relay.sh"
RUN="bash <(curl -fsSL $RAW_URL)"
PORT=8447                       # inbound port on EXIT (must match the PasarGuard inbound)
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
public_ip(){ curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || my_ip; }
ask(){ local v; read -rp "$1: " v; echo "$v"; }

enable_bbr(){
  grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf || \
    printf "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
  ok "BBR enabled"
}

check_hz_name(){   # $1 ip -> prints hostname or dies
  local host res
  host=$(hz_host "$1")
  res=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}' || true)
  [[ "$res" == "$1" ]] || die "$host does not resolve to $1 (this must be a Hetzner server with default rDNS)"
  echo "$host"
}

install_acme(){   # $1 email
  apt-get update -qq && apt-get install -y -qq socat curl cron openssl >/dev/null
  [[ -x $ACME ]] || curl -s https://get.acme.sh | sh -s email="$1" >/dev/null
}

issue_cert(){   # $1 host  $2 email  $3 out_dir  $4 reloadcmd  [hooks...]
  local host="$1" email="$2" out="$3" reload="$4"; shift 4
  mkdir -p "$out"
  if $ACME --list | grep -q "$host"; then
    ok "Certificate already exists — skipping issuance"
  elif ! $ACME --issue --standalone -d "$host" --keylength ec-256 --server letsencrypt "$@"; then
    warn "Let's Encrypt failed — trying ZeroSSL"
    $ACME --register-account -m "$email" --server zerossl >/dev/null
    $ACME --issue --standalone -d "$host" --keylength ec-256 --server zerossl "$@" || return 1
  fi
  $ACME --install-cert -d "$host" --ecc \
    --key-file "$out/hz.key" --fullchain-file "$out/hz.crt" \
    --reloadcmd "$reload" >/dev/null
  echo "$host" >"$STATE/cert_host"; echo "$out" >"$STATE/cert_dir"
  ok "Certificate installed"
}

print_cert(){
  local host dir exp
  host=$(cat "$STATE/cert_host" 2>/dev/null) || die "No certificate on this server"
  dir=$(cat "$STATE/cert_dir")
  exp=$(openssl x509 -enddate -noout -in "$dir/hz.crt" | cut -d= -f2)
  echo -e "\n${c_ylw}Certificate for $host — expires: $exp${c_off}"
  echo "########## CERTIFICATE (copy from BEGIN to last END) ##########"
  cat "$dir/hz.crt"
  echo "########## KEY ##########"
  cat "$dir/hz.key"
  echo "##########################"
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
  echo "${mnt:-/var/lib/pg-node}"
}

add_entries(){   # $1 = comma separated IPs
  local ip
  for ip in ${1//,/ }; do
    valid_ip "$ip" || die "Invalid IP: $ip"
    grep -qx "$ip" "$STATE/entries.list" 2>/dev/null || echo "$ip" >>"$STATE/entries.list"
  done
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
    while read -r ip; do [[ -n "$ip" ]] && ufw allow from "$ip" to any port "$PORT" proto tcp >/dev/null; done <"$list"
  fi
  ok "Port $PORT open only for: $(paste -sd, "$list")"
}

ask_entries_email(){   # sets ENTRIES EMAIL
  ENTRIES="${1:-}"; EMAIL="${2:-}"
  [[ -n "$ENTRIES" ]] || ENTRIES=$(ask "ENTRY server IP (several: comma separated)")
  [[ -n "$EMAIL"   ]] || EMAIL=$(ask "Email for the certificate")
  [[ -n "$ENTRIES" && -n "$EMAIL" ]] || die "Entry IP and email are required"
}

# Mode A: Hetzner exit, cert here
setup_exit(){
  local ip host cnt dir hook=()
  ask_entries_email "${1:-}" "${2:-}"
  say "Checking this server"
  ip=$(my_ip); host=$(check_hz_name "$ip")
  echo "IP: $ip   HOST: $host"
  command -v docker >/dev/null || die "Docker not found — install PasarGuard node first"
  cnt=$(node_container); dir=$(node_dir "$cnt")
  echo "Node container: $cnt   data dir: $dir"
  if ss -ltnp "sport = :80" | grep -q LISTEN; then
    if ss -ltnp "sport = :80" | grep -q '"xray"'; then
      warn "Port 80 is used by the node's Xray — node is stopped ~30s during issue/renew"
      hook=(--pre-hook "docker stop $cnt" --post-hook "docker start $cnt")
    else
      die "Port 80 busy by another program: $(ss -ltnp 'sport = :80' | tail -1)"
    fi
  fi
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 80/tcp >/dev/null; fi

  say "Certificate for $host"
  install_acme "$EMAIL"
  issue_cert "$host" "$EMAIL" "$dir/certs" "docker restart $cnt" "${hook[@]}" \
    || { docker start "$cnt" >/dev/null 2>&1 || true; die "Certificate issuance failed"; }
  docker start "$cnt" >/dev/null 2>&1 || true

  say "Firewall"; add_entries "$ENTRIES"; write_firewall
  say "BBR"; enable_bbr
  print_cert
  cat <<EOF

${c_grn}=================== EXIT DONE (Hetzner) ===================${c_off}
EXIT_HOST (SNI) = $host   (IP: $ip)

Now on the ENTRY server run:

   ${c_grn}$RUN entry $ip${c_off}
===========================================================
EOF
}

# Mode B: non-Hetzner exit, no cert here
setup_exit_ext(){
  local ip
  ask_entries_email "${1:-}" "${2:-}"
  say "Checking this server"
  command -v docker >/dev/null || die "Docker not found — install PasarGuard node first"
  node_container >/dev/null
  apt-get update -qq && apt-get install -y -qq curl >/dev/null
  ip=$(public_ip); echo "Public IP: $ip"
  say "Firewall"; add_entries "$ENTRIES"; write_firewall
  say "BBR"; enable_bbr
  cat <<EOF

${c_grn}=================== EXIT DONE (non-Hetzner) ===================${c_off}
No certificate on this server — it is issued on the ENTRY.

Now on the ENTRY server run:

   ${c_grn}$RUN entry-ext $ip $EMAIL${c_off}
================================================================
EOF
}

# ------------------------------------------------------------ ENTRY ---
install_haproxy(){
  if ss -ltnp "sport = :443" | grep -q LISTEN && ! ss -ltnp "sport = :443" | grep -q haproxy; then
    die "Port 443 is busy by another program: $(ss -ltnp 'sport = :443' | tail -1)"
  fi
  apt-get update -qq && apt-get install -y -qq haproxy openssl curl >/dev/null
}

save_exit(){   # $1 sni  $2 public ip  $3 connect ip
  touch "$STATE/exits.list"
  sed -i "\|^$1 |d" "$STATE/exits.list"
  echo "$1 $2 $3" >>"$STATE/exits.list"
}

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
  ok "HAProxy running"
}

test_exits(){
  local host ip conn
  sleep 1
  while read -r host ip conn; do
    if timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$host" </dev/null 2>/dev/null \
         | openssl x509 -noout -subject 2>/dev/null | grep -q "$host"; then
      ok "exit $ip  (SNI $host) — relay OK"
    else
      warn "exit $ip  (SNI $host) — no valid certificate yet (inbound/cert not active on exit, or this entry IP not allowed there)"
    fi
  done <"$STATE/exits.list"
}

print_hosts(){
  local ip host ehost eip conn
  ip=$(my_ip); host=$(hz_host "$ip")
  echo -e "\n${c_grn}=================== ENTRY DONE ===================${c_off}"
  echo "ENTRY_HOST (Address) = $host   (IP: $ip)"
  while read -r ehost eip conn; do echo "  exit $eip  ->  SNI = $ehost"; done <"$STATE/exits.list"
  echo "=================================================="
}

# Mode A entry (Hetzner exit)
setup_entry(){
  local pub="${1:-}" priv="${2:-}"
  [[ -n "$pub" ]] || pub=$(ask "EXIT server PUBLIC IP")
  valid_ip "$pub" || die "Invalid IP: $pub"
  [[ -z "$priv" ]] || valid_ip "$priv" || die "Invalid private IP: $priv"
  say "Installing HAProxy"; install_haproxy
  save_exit "$(hz_host "$pub")" "$pub" "${priv:-$pub}"
  say "HAProxy"; write_haproxy
  say "BBR"; enable_bbr
  say "Testing relay"; test_exits
  print_hosts
}

# Mode B entry (non-Hetzner exit): cert for THIS entry's own hostname
setup_entry_ext(){
  local pub="${1:-}" email="${2:-}" ip host
  [[ -n "$pub"   ]] || pub=$(ask "EXIT server PUBLIC IP")
  [[ -n "$email" ]] || email=$(ask "Email for the certificate")
  valid_ip "$pub" || die "Invalid IP: $pub"
  say "Checking this server"
  ip=$(my_ip); host=$(check_hz_name "$ip")
  echo "IP: $ip   HOST: $host"
  if ss -ltnp "sport = :80" | grep -q LISTEN; then
    die "Port 80 is busy: $(ss -ltnp 'sport = :80' | tail -1)"
  fi
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 80/tcp >/dev/null; fi
  say "Installing HAProxy"; install_haproxy
  say "Certificate for $host"
  install_acme "$email"
  issue_cert "$host" "$email" "$STATE/certs" "true" || die "Certificate issuance failed"
  save_exit "$host" "$pub" "$pub"
  say "HAProxy"; write_haproxy
  say "BBR"; enable_bbr
  print_cert
  say "Testing relay"; test_exits
  warn "If the test failed: add the certificate above to the inbound first, then run:  $RUN status"
  print_hosts
}

# ----------------------------------------------------------- STATUS ---
status(){
  local any=0
  if [[ -f "$STATE/entries.list" ]]; then
    any=1; say "EXIT status"
    if ss -tlnp | grep -q ":$PORT "; then ok "Listening on $PORT"; else warn "Nothing listening on $PORT"; fi
    echo "Allowed entries: $(paste -sd, "$STATE/entries.list")"
  fi
  if [[ -f "$STATE/cert_host" ]]; then
    any=1
    echo "Certificate: $(cat "$STATE/cert_host") — expires $(openssl x509 -enddate -noout -in "$(cat "$STATE/cert_dir")/hz.crt" | cut -d= -f2)"
  fi
  if [[ -f "$STATE/exits.list" ]]; then
    any=1; say "ENTRY status"
    if systemctl is-active --quiet haproxy; then ok "HAProxy running"; else warn "HAProxy NOT running"; fi
    test_exits
  fi
  [[ $any -eq 1 ]] || warn "Nothing set up on this server yet"
}

# ------------------------------------------------------------- MAIN ---
menu(){
  echo -e "${c_cyan}
  Pronet Relay
  ------------
  EXIT server (PasarGuard node):
    1) EXIT is Hetzner
    2) EXIT is another datacenter (Turkey, ...)
  ENTRY server (Hetzner, not a node):
    3) ENTRY for a Hetzner exit
    4) ENTRY for a non-Hetzner exit
  Tools:
    5) Show certificate again
    6) EXIT: allow another entry IP
    7) Status / test
    0) Quit${c_off}"
  case "$(ask 'Choose')" in
    1) setup_exit ;;
    2) setup_exit_ext ;;
    3) setup_entry ;;
    4) setup_entry_ext ;;
    5) print_cert ;;
    6) add_entries "$(ask 'New entry IP')"; write_firewall ;;
    7) status ;;
    *) exit 0 ;;
  esac
}

case "${1:-}" in
  exit)      setup_exit "${2:-}" "${3:-}" ;;
  exit-ext)  setup_exit_ext "${2:-}" "${3:-}" ;;
  entry)     setup_entry "${2:-}" "${3:-}" ;;
  entry-ext) setup_entry_ext "${2:-}" "${3:-}" ;;
  cert)      print_cert ;;
  add-entry) add_entries "${2:-$(ask 'New entry IP')}"; write_firewall ;;
  status)    status ;;
  "")        menu ;;
  *)         die "Unknown command: $1" ;;
esac
