# Pronet Relay

VLESS + TCP + TLS with a Hetzner rDNS certificate, behind an HAProxy relay (PROXY protocol v2).

```
user --443--> ENTRY (HAProxy) --8447--> EXIT (PasarGuard node)
```

## Install / run

On **both** servers (EXIT first, then ENTRY):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-relay/main/relay.sh)
```

Menu:

1. Setup EXIT (PasarGuard node must already be installed and connected)
2. Setup ENTRY
3. EXIT: show certificate again (after renewal)
4. EXIT: allow another entry IP
5. ENTRY: add another exit
6. Status / test

Direct commands:

```bash
# EXIT
bash <(curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-relay/main/relay.sh) exit ENTRY_IP EMAIL
# ENTRY (command is printed at the end of the EXIT setup)
bash <(curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-relay/main/relay.sh) entry EXIT_IP
```
