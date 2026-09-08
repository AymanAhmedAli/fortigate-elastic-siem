# FortiGate + Active Directory SIEM with Elastic Stack

Multi-source SIEM built from scratch in a virtualized lab. FortiGate firewall logs and Windows Active Directory events are normalized to ECS, indexed in Elasticsearch, and visualized in two Kibana dashboards. Detection capability validated against a live port scan.

---

## Architecture

```
FortiGate VM64 (port1)
    │  syslog UDP 5144
    ▼
Logstash ── grok → kv → eventtime parsing → ECS mapping → geoip
    │
    ▼
Elasticsearch 8.19.21 (Ubuntu 24.04, single node)
    ▲
    │  Winlogbeat 8.19.21 + ingest pipelines
    │
Windows Server 2022 DC (test.local) ── GPO ──> Windows Client
    │
    ▼
Kibana 8.19.21
```

## Stack

| Component | Version |
|---|---|
| FortiGate | VM64 v7.0.5 build0304 |
| Elasticsearch | 8.19.21 |
| Kibana | 8.19.21 |
| Logstash | 8.19.21 |
| Winlogbeat | 8.19.21 |
| Windows Server | 2022 (Domain Controller) |
| Host OS | Ubuntu 24.04 |
| Hypervisor | VMware (bridged networking) |

## Data volume

| Source | Events | Notes |
|---|---|---|
| Windows / Active Directory | 25,207 | 73% ECS-categorized |
| FortiGate | 63,452 | 62,623 denied (99%) |

ECS categories present: `authentication`, `iam`, `configuration`, `process`, `driver`, `network`

---

## Dashboards

### Windows / Active Directory

| Panel | Type | Notes |
|---|---|---|
| Events Over Time by Category | Area, stacked | Top 5 `event.category` |
| Events by Category | Bar | Top 10 |
| Top Security Actions | Table | Top 15 `event.action`, filtered to `event.module: security` |
| Total Events | Metric | |
| Failed Logon Attempts | Metric | `event.code: 4625` |
| Top Users in Events | Bar | Machine accounts excluded |

### FortiGate

| Panel | Type | Notes |
|---|---|---|
| Firewall Activity Over Time | Line | Breakdown by `action` |
| Top Source IPs | Bar | Top 10 `source.ip` |
| Denied Connections | Metric | `action: deny` |
| Total Firewall Events | Metric | |
| Unique Ports Scanned | Metric | Unique count of `destination.port`, `action: deny` |
| Top Active Ports | Table | Legitimate traffic baseline (`accept` / `close`) |

Exported saved objects are in `dashboards/` and can be imported via
**Stack Management → Saved Objects → Import**.

---

## Detection validation

A full TCP SYN scan was run against the firewall to verify end-to-end pipeline function:

```bash
sudo nmap -sS -Pn -p- <firewall-ip>
```

Observed in Elasticsearch within seconds:

| Metric | Value |
|---|---|
| Total firewall events | 63,452 |
| `action: deny` | 62,623 (99%) |
| Distinct source IPs generating denies | 1 |
| Unique destination ports probed | 3,058 |

Single source, thousands of distinct ports, near-total deny rate — a textbook port scan signature, and exactly the shape a detection rule should key on.

`-Pn` was required because the firewall does not respond to ICMP; without it nmap
aborts with `Host seems down` even though the device is reachable and actively
sending syslog.

### Security finding

The scan revealed **telnet (port 23) exposed** on the management interface — cleartext
credentials on a perimeter device. Remediated:

```
config system interface
    edit port1
        unset allowaccess
        set allowaccess ping https ssh
    next
end
```

---

## Key lessons

### Index mapping must be defined before the first document

Elasticsearch infers mappings from the first document it receives. With no template in
place, fields land as `text` and aggregations fail permanently:

```
Fielddata is disabled on [source.ip]. Text fields are not optimised
for operations that require per-document field data like aggregations
```

An existing index cannot be remapped. Recovery meant routing to a new pattern
(`fortigate-v2-*`) backed by an explicit template at `priority: 600` — see
`configs/index-templates.json`.

### The `type` field collides with FortiGate's own schema

FortiGate uses `type` natively (`traffic`, `event`, `utm`). Setting `type => "fortigate"`
on the Logstash input means `kv` overwrites it, silently breaking every downstream
`if [type] == ...` conditional. Use `tags => ["fortigate"]` instead.

This one cost the most time to find, because nothing errors — logs keep flowing, they
just stop being enriched.

### Parse the vendor's absolute timestamp, not its formatted local time

FortiOS 7.0.5 treats Cairo as GMT+2, but Egypt observes GMT+3 (EEST) since DST returned
in 2023. The OS timezone database predates the change, so the device's displayed clock is
permanently offset — and no manual correction survives an NTP sync.

Symptoms: every `@timestamp` landed hours in the future, relative time ranges in Kibana
returned nothing, and correlation between firewall and AD events would have been
impossible.

The fix is to ignore `date`/`time` entirely and parse `eventtime`, which FortiGate emits
as epoch nanoseconds in absolute UTC:

```ruby
if [eventtime] {
  ruby {
    code => "
      et = event.get('eventtime').to_s
      event.set('event_epoch_ms', (et[0,13]).to_i) if et.length >= 13
    "
  }
  date {
    match => [ "event_epoch_ms", "UNIX_MS" ]
    target => "@timestamp"
    remove_field => [ "event_epoch_ms", "date", "time", "tz" ]
  }
} else {
  # fallback for log types without eventtime
  mutate { add_field => { "fgt_timestamp" => "%{date} %{time}" } }
  date {
    match => [ "fgt_timestamp", "yyyy-MM-dd HH:mm:ss" ]
    timezone => "Etc/GMT-2"
    target => "@timestamp"
    remove_field => [ "fgt_timestamp", "date", "time" ]
  }
}
```

Verified: a scan run at 12:25 EEST produced `@timestamp: 09:25:52.460Z` — a clean
three-hour offset, with sub-second precision confirming the value came from the epoch
field rather than a formatted string.

Time sync is a correctness prerequisite for a SIEM, not an optimization.

### A log source on DHCP breaks correlation

The firewall's `port1` was left on DHCP and its address changed mid-project. Syslog
delivery survived (the destination is the collector, not the source), but every
correlation rule keyed on the source IP would have silently stopped matching, and the
device became unreachable at its documented address.

Log sources in production need static addressing or a DHCP reservation.

### `cardinality` is approximate by design

Elasticsearch's `cardinality` aggregation uses HyperLogLog++. It is accurate up to
`precision_threshold` (default 3,000 distinct values) and degrades beyond it. For a
"unique ports" metric used to detect scanning, that ceiling matters:

```json
GET fortigate-v2-*/_search
{
  "size": 0,
  "query": { "term": { "action": "deny" } },
  "aggs": {
    "unique_ports": {
      "cardinality": {
        "field": "destination.port",
        "precision_threshold": 40000
      }
    }
  }
}
```

Raising the threshold moved the count from 3,418 to 3,398 — a 0.6% error at this volume,
but one worth knowing about before building an alert on the number.

### Winlogbeat only categorizes channels it has ECS mappings for

The routing pipeline branches on four channels: Security, Sysmon, Windows PowerShell, and
PowerShell/Operational. Events from **System** and **Application** pass through without
`event.category` — 27% of events collected here. Not a bug; a design constraint worth
knowing before building category-based visualizations.

Enabling Process Creation auditing (event 4688) or installing Sysmon significantly
enriches the `process`, `network`, `file`, and `registry` categories.

### `user.name` is not always the actor

Winlogbeat populates `user.name` from either `SubjectUserName` (the actor) or
`TargetUserName` (the object of the action), depending on event code. Event 4738 (user
account modified) surfaced `ANONYMOUS LOGON` in `user.name` — a field value carried from
the event data, not an actual anonymous logon.

For accurate attribution: `user.name` for the actor, `user.target.name` for the target.
Worth verifying field semantics before building any correlation logic on identity.

### Single-node clusters default to yellow health

Replica shards have nowhere to allocate. Fixed for existing indices and inherited by new
ones via component template:

```json
PUT _component_template/winlogbeat-single-node
{ "template": { "settings": { "index.number_of_replicas": 0 } } }
```

---

## Repository contents

```
configs/
  fortigate.conf          Logstash pipeline (credentials redacted)
  winlogbeat.yml          Winlogbeat configuration
  index-templates.json    Elasticsearch index templates
setup/
  01-elasticsearch.md     Install, network.host, initial passwords
  02-logstash.md          Pipeline setup, syslog input
  03-winlogbeat-gpo.md    GPO-based agent deployment
  04-fortigate-syslog.md  Syslog + local-in logging configuration
dashboards/
  siem-dashboards.ndjson  Exported Kibana saved objects
screenshots/
```

## Notes

All credentials in this repository are placeholders. Lab addresses are RFC 1918 private
ranges from an isolated environment. Elasticsearch credentials in the live deployment are
stored in the Logstash keystore rather than in plaintext config.
---

## 👤 Author

**Ayman Ahmed**
IT Specialist | Network Security | Penetration Testing

[![GitHub](https://img.shields.io/badge/GitHub-AymanAhmedAli-black?style=flat&logo=github)](https://github.com/AymanAhmedAli)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/aymanahmedali/)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Platinum-red?style=flat&logo=tryhackme)](https://tryhackme.com/p/aymanahmed)
