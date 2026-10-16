# Rule 2 — Possible Brute Force - Failed Logons

## Status
**Implemented and validated in Kibana Detection Engine on 2026-10-16.**

This file documents the currently implemented rule. Older two-tier design ideas are retained below as historical design notes, but the active validated rule is the single threshold rule described here.

## Objective
Detect repeated Windows network logon failures from the same source IP against the same target account before the Active Directory account lockout threshold is reached.

## Active Rule Configuration

| Setting | Value |
|---|---|
| Name | `Possible Brute Force - Failed Logons` |
| Rule type | Threshold |
| Index pattern | `winlogbeat-*` |
| Query language | KQL |
| Custom query | `event.code: "4625" AND winlog.event_data.LogonType: "3"` |
| Group by | `source.ip`, `winlog.event_data.TargetUserName` |
| Threshold | `>= 4` |
| Count | All results |
| Severity | Medium |
| Risk score | 47 |
| Runs every | 1 minute |
| Additional look-back | widened during tuning to cover observed authentication delay |
| Actions | None |

## Why Threshold 4?
The current AD account lockout threshold is **5 failed attempts**.

Alerting at 5 would fire at the same point the account locks. The active rule therefore uses a threshold of **4** so the detection can provide an early-warning signal before the fifth failure causes lockout.

```text
4 effective failures → Detection alert
5 effective failures → AD lockout threshold
```

## Why Event ID 4625?
Windows Security Event ID **4625** represents a failed logon. The validated test produced:

```text
event.code: 4625
source.ip: 10.10.10.30
winlog.event_data.LogonType: 3
winlog.event_data.AuthenticationPackageName: NTLM
```

`LogonType: 3` narrows the detection to network logons and matches the SMB authentication simulation used for validation.

## Grouping Logic
The threshold rule groups by:

```text
source.ip
winlog.event_data.TargetUserName
```

This means the rule looks for repeated failures from the **same source** against the **same target user**, rather than simply counting all 4625 events in the environment.

## Timing / Look-back Tuning
During validation, failed SMB authentication attempts sometimes took approximately 15–21 seconds each. A set of sequential failures could therefore span multiple one-minute rule executions.

The initial narrow look-back was widened during tuning so that all effective failures could be evaluated together.

This is an important detection-engineering lesson: the time window must be based on observed telemetry timing, not just the intended attack speed.

## Validation Result
A clean test account was used and stopped at:

```text
badPwdCount = 4
LockedOut   = False
```

Four relevant Event ID 4625 documents were visible in Elastic. Kibana then generated:

```text
Possible Brute Force - Failed Logons
Severity: Medium
Risk score: 47
Source: 10.10.10.30
Alert count: 1
```

The full validated chain was:

```text
Windows Client
→ failed network authentication
→ DC Event ID 4625
→ Winlogbeat
→ Elasticsearch
→ Kibana threshold rule
→ alert
```

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Brute Force | T1110 |

## False Positive Considerations
Potential benign causes include:
- a legitimate user repeatedly mistyping a password;
- stale cached credentials or mapped resources;
- a service/task using an outdated password;
- administrative testing.

Analyst triage should review source IP, target account, timing, authentication package, surrounding logon activity, and whether a successful logon follows the failures.

## Severity Escalation — Future Work
The current rule is Medium severity. A future correlation rule should raise severity when the failed-attempt burst is followed by a successful logon (`4624`) for the same account/source, because that changes the scenario from attempted guessing to possible account compromise.

## Historical Design Note
An earlier version of this documentation proposed a two-tier model:
- 3 failures / 5 minutes → Low early warning;
- 5 failures / 60 seconds → Medium lockout confirmation.

That model was useful during design review, but the current implemented/validated rule uses **4 failures** as a practical pre-lockout threshold aligned with the lab's AD policy.

## Related Files
- `README.md` — current end-to-end validation and evidence summary
- `troubleshooting.md` — infrastructure, telemetry, and rule-tuning journey
- `query.json` — investigation/aggregation query aligned to current event fields
- `simulation.md` — historical simulation from the previous topology
- `investigation.md` — historical evidence from the previous topology
