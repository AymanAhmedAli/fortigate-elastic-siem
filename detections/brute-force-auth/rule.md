# Rule 2 — Failed Login Brute Force Detection

## Overview
Detects a potential brute force attack when a single source IP
generates multiple failed authentication attempts against the same
destination IP and username within a short time window.

## Detection Logic

IF:
event.code == 4625
AND event.outcome == "failure"
AND winlog.logon.type == "Network"
AND same source.ip
AND same destination.ip
AND same user.name
AND failed attempt count >= 5
AND within a 60 second window
THEN:
Generate a High Severity Alert: "Potential Brute Force Detected"
Include source.ip, destination.ip, user.name, and attempt count


## Parameters

| Parameter | Value |
|---|---|
| Event ID | 4625 (Failed Logon) |
| Failed attempts threshold | 5+ |
| Time window | 60 seconds |
| Grouping | source.ip + destination.ip + user.name |
| Severity | High (initial) |

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Brute Force | T1110 |

## Rationale
A legitimate user who mistypes a password typically fails once or
twice before succeeding or giving up. Five or more failed attempts
against the same account from the same source within one minute is
inconsistent with normal human behavior and is consistent with
automated credential-guessing tools.

## Severity Reasoning
Rated High rather than Medium because failed authentication attempts
represent a direct attempt at unauthorized access — unlike
reconnaissance activity (e.g. port scanning), a successful brute
force attempt grants the attacker a foothold immediately, with no
further steps required.

**Escalation note (future work):** severity should increase to
Critical if any failed-attempt burst is immediately followed by a
successful logon (event.code 4624) for the same account — this would
indicate the brute force succeeded, not just that an attack was
attempted. Not implemented in this initial rule; see
`investigation.md` for details.

## Related Files
- `query.json` — Elasticsearch aggregation query used to validate this rule
- `simulation.md` — How the attack was simulated for testing
- `investigation.md` — Evidence and findings from the test run
