# Simulation — Vertical Port Scan

## Objective
Generate realistic port scan traffic through the FortiGate firewall
to validate Rule 1 (Vertical Port Scan Detection).

## Environment
- Attacker: Kali Linux (172.18.183.50)
- FortiGate: FGT-VM64-IGBMCW (172.18.183.1 LAN / port2 WAN)
- Target: 8.8.8.8 (external, routed through FortiGate port2)

## Prerequisite — Routing Fix
Initial scans against the FortiGate's own management IP produced no
traffic logs, because management-plane traffic (admin login/logout)
is logged separately from forwarded/routed traffic. Additionally,
Kali had a direct default route to the hypervisor network that
bypassed the FortiGate entirely.

Fix: removed Kali's direct default route and replaced it with the
FortiGate LAN interface as the sole gateway, forcing all outbound
traffic through the firewall's `LAN-to-WAN` policy:

```bash
sudo ip route del default via <hypervisor_gateway> dev eth0
sudo ip route add default via 172.18.183.1 dev eth0
```

## Attack Commands

```bash
# Scan 1
nmap -p 1-100 8.8.8.8

# Scan 2
nmap -p 1-1000 8.8.8.8
```

## Result
Both scans were successfully logged by the FortiGate and forwarded
to Elasticsearch via Logstash, confirming the full pipeline:

Kali (attacker) → FortiGate (port1, LAN-to-WAN policy, NAT)
→ port2 (WAN) → 8.8.8.8
→ syslog → Logstash (UDP 5144) → Elasticsearch


See `investigation.md` for the resulting evidence and analysis.
