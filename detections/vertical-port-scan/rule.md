# Rule 1 — Vertical Port Scan Detection

## Overview
Detects a potential vertical port scan when a single source IP
connects to an unusually high number of unique destination ports
on the same destination IP within a short time window.

## Detection Logic

IF:
same source.ip
AND same destination.ip
AND unique destination.port count > 20
AND within a 60 second window
THEN:
Alert: "Potential Vertical Port Scan Detected"


## Parameters

| Parameter | Value |
|---|---|
| Unique destination ports (threshold) | 20+ |
| Time window | 60 seconds |
| Severity | Medium (initial) |

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Active Scanning: Vulnerability Scanning | T1595.002 |

## Rationale
A legitimate client connecting to a single external IP typically
uses 1-2 destination ports (e.g. HTTPS on 443, DNS on 53). A sudden
spike to dozens of unique ports against the same destination IP
within seconds is a strong behavioral signature of reconnaissance
activity (port scanning), not normal application traffic.

## Related Files
- `query.json` — Elasticsearch aggregation query used to validate this rule
- `simulation.md` — How the attack was simulated for testing
- `investigation.md` — Evidence and findings from the test run
