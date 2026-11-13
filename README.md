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

Two modes:

- **Exit is Hetzner** — certificate on the exit, SNI = exit hostname. One entry can serve many Hetzner exits (routed by SNI).
- **Exit is another datacenter** (Turkey, ...) — certificate on the entry, SNI = entry hostname. One entry serves one such exit.

Menu:

1. EXIT is Hetzner
2. EXIT is another datacenter
3. ENTRY for a Hetzner exit (run again to add more exits)
4. ENTRY for a non-Hetzner exit
5. Show certificate again (after renewal)
6. EXIT: allow another entry IP
7. Status / test

The EXIT setup prints the exact command to run on the ENTRY.
