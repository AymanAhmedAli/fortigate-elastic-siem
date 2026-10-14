# 📋 SIEM Project — Technical Notes & Lessons Learned

> Detailed notes from building the FortiGate + Active Directory + Elastic Stack SIEM

---

## ✅ What Was Built

### Windows / AD Dashboard
6-panel Kibana dashboard covering:
- Events Over Time by Category
- Events by Category  
- Top Security Actions
- Total Events (~20,600)
- Failed Logon Attempts (event.code: 4625)
- Top Users in Events

### FortiGate Pipeline (Rebuilt)
- Full `kv` parsing of key=value pairs
- ECS field mapping
- GeoIP enrichment
- New index pattern: `fortigate-v2-*`
- Port scan detection confirmed ✅

### Results
- 112,533+ FortiGate documents
- 20,132+ Windows documents  
- Port scan signature detected (~45,000 unique ports)

---

## ⚠️ Historical Issue — Timestamp Offset

The earlier FortiOS 7.0.5 deployment treated Cairo as GMT+2; this is not a verified issue on the current FortiOS 7.6.7 build3704.
Egypt moved to GMT+3 (EEST) in 2023.
**Fix:** Use `eventtime` field (UTC epoch) instead of `date`/`time`.

---

## 📚 Key Lessons Learned

1. **Index mapping must be set before first document**
2. **`type` field conflicts with FortiGate** — use `tags` instead
3. **Time sync is critical** — wrong timestamps break event correlation
4. **Winlogbeat categorizes 4 channels only** — System/Application events have no `event.category`
5. **`user.name` is not always the actor** — check event code context
6. **Single-node cluster = yellow** — set `number_of_replicas: 0`

---

## 🔑 Reference

The trusted infrastructure now shares one internal LAN, `10.10.10.0/24`, behind FortiGate. Kali is isolated on `10.10.20.0/24`; its traffic to the internal LAN must traverse FortiGate for forwarding-policy logging. Keep the virtual networks separate and avoid secondary adapters or routes that bypass the firewall.

| System / interface | Current lab address | Role |
|---|---|---|
| FortiGate port1 | 172.27.247.135/20 | Dynamic lab WAN; address may change |
| FortiGate port2 | 10.10.10.1/24 | Internal LAN gateway |
| Domain Controller / DNS | 10.10.10.10 | Trusted LAN |
| Ubuntu Elastic / Kibana / Logstash | 10.10.10.20 | Trusted LAN collector and scan target |
| Windows Client | 10.10.10.30 | Trusted LAN |
| FortiGate port3 | 10.10.20.1/24 | Attacker segment gateway |
| Kali | 10.10.20.10 | Isolated attacker segment |

```text
Dynamic lab WAN -> port1 FortiGate-VM64 (FortiOS 7.6.7 build3704)
                       | port2 10.10.10.1 -> trusted LAN 10.10.10.0/24
                       |                   DC/DNS .10, Ubuntu .20, Client .30
                       | port3 10.10.20.1 -> attacker LAN 10.10.20.0/24
                                           Kali 10.10.20.10

FortiGate -> syslog UDP/5144 -> Logstash -> Elasticsearch -> Kibana
Windows/AD -> Winlogbeat -> Elasticsearch -> Kibana
```

The Elastic services run together on Ubuntu `10.10.10.20`. Internal systems use `10.10.10.1` as their gateway and `10.10.10.10` for lab DNS; Kali uses `10.10.20.1` as its gateway. The current scan path is port3 -> policy 2 (`ATTACKER-to_LAN`) -> port2 -> `10.10.10.20`.

---

## ⏰ Important Dates

| Date | Event |
|------|-------|
| Sep 19, 2026 | FortiGate evaluation license expires |

---

*Part of the [fortigate-elastic-siem](https://github.com/AymanAhmedAli/fortigate-elastic-siem) project*
