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

## ⚠️ Known Issue — Timestamp Offset

FortiOS 7.0.5 treats Cairo as GMT+2.
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

| Component | Value |
|-----------|-------|
| FortiGate | 172.18.178.220 |
| ELK Stack | 172.18.183.113 |
| DC | 172.18.183.10 |
| Client | 172.18.183.20 |
| Syslog port | UDP 5144 |
| Kibana | HTTP 5601 |
| Elasticsearch | HTTPS 9200 |

---

## ⏰ Important Dates

| Date | Event |
|------|-------|
| Sep 19, 2026 | FortiGate evaluation license expires |

---

*Part of the [fortigate-elastic-siem](https://github.com/AymanAhmedAli/fortigate-elastic-siem) project*
