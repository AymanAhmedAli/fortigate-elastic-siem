# Port scan detection engineering — segmented lab

This validation uses a segmented lab where attack traffic must cross FortiGate before reaching the trusted network.

```text
Kali attacker 10.10.20.10 ----\
                               > attacker LAN 10.10.20.0/24
Windows test host 10.10.20.30 -/        |
                                        v
                              FortiGate port3 10.10.20.1
                                        |
                              policy 2 ATTACKER-to_LAN
                                        |
                              FortiGate port2 10.10.10.1
                                        |
                              trusted LAN 10.10.10.0/24
                                        |
                              Ubuntu / Elastic 10.10.10.20
```

FortiGate telemetry path:

```text
Attack traffic -> FortiGate -> syslog UDP/5144 -> Logstash -> Elasticsearch -> Kibana -> Detection Engine
```

These are RFC1918 lab addresses and authorized test systems only.

## Detection rule

A live Kibana threshold rule was created and enabled:

- **Rule name:** `Possible Port Scan - FortiGate`
- **Index pattern:** `fortigate-v2-*`
- **Rule type:** Threshold
- **Custom query:** `*`
- **Group by:** `source.ip`, `destination.ip`
- **Event threshold:** `>= 20`
- **Cardinality field:** `destination.port`
- **Unique values:** `>= 20`
- **Severity:** Medium
- **Risk score:** 47
- **Runs every:** 1 minute
- **Additional look-back:** 1 minute

The rule was initially validated with a hard-coded Kali source filter, then generalized to `*` so the detection keys on behavior rather than one known scanner IP.

Detection logic:

```text
Any source IP
  -> same destination IP
  -> at least 20 matching events
  -> at least 20 unique destination ports
  -> generate alert
```

This is a lab-tuned threshold, not a claimed production baseline.

## Validation matrix

| Test | Source | Tool / behavior | Result |
|---|---|---|---|
| Fast scan | `10.10.20.10` | Nmap SYN scan, ports 1-100 | Detected |
| Slow scan | `10.10.20.10` | Nmap with 500 ms scan delay | Detected |
| Normal traffic | `10.10.20.10` | `curl` to one service + ICMP ping | No alert |
| Different source/tool | `10.10.20.30` | PowerShell `TcpClient` scan, ports 1-100 | Detected |

The fourth test is important: the rule detected the same behavior from a different host using a different scanning method, confirming that the final rule is not tied to Kali or Nmap.

## Test 1 — fast Nmap scan

```bash
nmap -sS -Pn -p 1-100 10.10.10.20
```

Recorded Elastic evidence:

- Matching events: `100`
- Unique destination ports: `100`
- Approximate indexed event span: `10 ms`

Representative FortiGate fields:

```text
source.ip: 10.10.20.10
destination.ip: 10.10.10.20
destination.port: 86
policyid: 2
policyname: ATTACKER-to_LAN
subtype: forward
action: server-rst
```

`subtype=forward` means the session crossed the firewall rather than being local FortiGate traffic. `server-rst` indicates a TCP reset from the destination/server side; during scanning this is commonly seen when a destination port is closed. It is not itself a firewall deny or proof of compromise.

## Test 2 — slower Nmap scan

```bash
nmap -sS -Pn --scan-delay 500ms -p 1-100 10.10.10.20
```

Recorded Elastic evidence:

- Matching events: `111`
- Unique destination ports: `100`
- First event: `2026-10-14T21:40:04.110Z`
- Last event: `2026-10-14T21:41:05.000Z`
- Indexed event span: `60.89 s`

This demonstrated why document count and unique-port count must be treated separately: one scan can produce more log documents than distinct ports.

## Normal-traffic check

Simple normal traffic was generated from Kali:

```bash
curl http://10.10.10.20:5601
ping -c 5 10.10.10.20
```

No new alert was generated. This is a useful first false-positive check, but it is not enough to claim production-quality tuning; broader baseline traffic is still required.

## Test 3 — PowerShell scanner from a different source

The Windows client was temporarily moved to the attacker segment and configured as:

```text
IP:      10.10.20.30/24
Gateway: 10.10.20.1
DNS:     10.10.10.10
```

This forced its traffic to `10.10.10.20` through FortiGate. A PowerShell TCP scan then tested ports 1-100 using `System.Net.Sockets.TcpClient`.

Recorded Elastic evidence:

- Total matching events: `496`
- Unique destination ports: `100`
- First event: `2026-10-15T12:29:13.370Z`
- Last event: `2026-10-15T12:32:48.220Z`
- Duration: approximately `214.85 s`

One-minute histogram results:

| UTC minute | Documents | Unique destination ports |
|---|---:|---:|
| 12:29 | 107 | 22 |
| 12:30 | 138 | 31 |
| 12:31 | 145 | 32 |
| 12:32 | 106 | 24 |

The alert appeared after ingestion/rule execution, bringing the validation total to four alerts across the test sequence. This confirmed the generalized rule could detect port-scanning behavior from a different source and tool.

## Detection-engineering lessons

### Validate narrowly, then generalize

The rule was first tested with:

```text
source.ip: "10.10.20.10"
```

After validation, the custom query was changed to:

```text
*
```

The behavioral threshold remained unchanged. Re-testing confirmed detection still worked.

### Count unique ports, not only documents

A scan can create several FortiGate events per destination port. The PowerShell test produced 496 matching documents but only 100 unique destination ports. `cardinality(destination.port)` is therefore more meaningful than raw event count for this behavior.

### Slow behavior can cross rule windows

The PowerShell scan lasted about 214.85 seconds, yet each observed one-minute bucket still exceeded 20 unique destination ports. This made it a useful test of scheduling, look-back and threshold behavior rather than only scanner speed.

### Sensor placement matters

When the Windows client was on the same trusted subnet as Ubuntu, traffic could stay at Layer 2 and bypass FortiGate. Moving the client temporarily to the attacker segment forced the test path through the firewall so the network sensor could observe it.

A detection can only analyze traffic visible to its telemetry source.

## Current status

The first custom port-scan rule is now **live and validated in the lab** against:

- fast Nmap scanning
- slower Nmap scanning
- a PowerShell TCP scanner
- a second source host
- simple normal traffic without a false alert

This is sufficient for a portfolio milestone, but not a claim of production-ready coverage. Future tuning should include broader normal baselines, additional scan patterns, suppression/deduplication behavior, UDP scanning, horizontal scanning, and response workflow testing.

## Next steps

1. Preserve screenshots/evidence without exposing credentials.
2. Expand false-positive testing with realistic multi-service traffic.
3. Test additional scan patterns and thresholds.
4. Build triage/investigation steps for the generated alert.
5. Map the behavior to MITRE ATT&CK.
6. Continue to the next Mini-SOC scenario: brute-force authentication detection.

See [queries.md](queries.md) for the Elasticsearch investigation queries used to validate these results.
