# Port scan validation — segmented lab

This validation uses Kali `10.10.20.10` on the attacker segment and Ubuntu Elastic/Logstash/Kibana `10.10.10.20` on the trusted LAN. These are private lab IPs, not production targets. See the [current architecture](../../README.md#architecture).

Kali -> FortiGate port3 (`10.10.20.1`) -> policy 2 (`ATTACKER-to_LAN`) -> port2 (`10.10.10.1`) -> Ubuntu. The separate segments force attack traffic across FortiGate rather than directly between guests on one LAN. Forwarded traffic is shipped as FortiGate -> syslog UDP/5144 -> Logstash -> Elasticsearch -> Kibana. Windows/AD telemetry separately follows Winlogbeat -> Elasticsearch -> Kibana.

## Recorded observations

The results below were supplied from the lab investigation; they have not been re-run against a live Elasticsearch session during this documentation update.

| Test | Matching events | Unique destination ports | Event timestamp span |
|---|---|---|---|
| Fast scan | 100 | 100 | Approximately 10 ms |
| Slow scan | 111 | 100 | Approximately 60.89 seconds |

The exact fast-scan command and absolute time bounds were not supplied, so they are not reconstructed here. The span measures indexed event timestamps, not necessarily the scanner's wall-clock runtime.

Slow scan, run from Kali against the lab Ubuntu host:

```bash
sudo nmap -sS -Pn --scan-delay 500ms -p 1-100 10.10.10.20
```

Slow-scan timestamps (UTC):

- First event: `2026-10-14T21:40:04.110Z`
- Last event: `2026-10-14T21:41:05.000Z`
- Difference: `60,890 ms` = `60.89 s`

Representative fields from the current scan investigation:

```text
source.ip: 10.10.20.10
destination.ip: 10.10.10.20
subtype: forward
action: server-rst
policyid: 2
policyname: ATTACKER-to_LAN
```

`server-rst` describes a reset from the server side; it is not a firewall deny or proof that a service was compromised. A deny-only dashboard or query can miss these forwarded scan events. There are more events than distinct ports in the slow run; count events and unique ports separately rather than assuming one document per probe.

## Detection tuning

Group by `source.ip` and `destination.ip` and count distinct `destination.port`. A candidate threshold of 20 unique ports within 10 seconds could miss slower scans. At a nominal 500 ms delay, 20 probes already take about 10 seconds; timing variation, retries, event timestamps, window boundaries, and a strict `> 20` comparison can move the scan below the trigger. The observed slow run spans more than 60 seconds.

Evaluate a longer look-back (for example 2 minutes) alongside the short-window rule, scheduling overlap and alert deduplication. This is a tuning candidate, not a validated production threshold. Re-test with normal traffic and slower scans, measure false positives, and verify actual Kibana alert generation before claiming deployed detection coverage. The earlier [vertical scan rule](../vertical-port-scan/rule.md) used a 60-second design; it is separate from the 10-second candidate discussed here.

Use [queries.md](queries.md) to reproduce cardinality and timestamp analysis. No raw event export, credentials, or new screenshots are included.
