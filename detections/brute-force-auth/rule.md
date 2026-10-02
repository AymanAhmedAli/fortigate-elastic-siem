# Rule 2 — Failed Login Brute Force Detection

## Overview
Detects a potential brute force attack when a single source IP
generates multiple failed authentication attempts against the same
destination IP and username within a short time window.

## Detection Logic — Two-Tier Design

This rule uses two severity tiers rather than a single threshold,
because the AD lockout threshold (5 attempts) and a useful early
warning threshold are not the same number — alerting only at 5 means
the alert fires at the same moment the account locks, confirming
damage rather than warning before it.

### Tier 1 — Early Warning (Low Severity)

IF:
event.code == 4625
AND event.outcome == "failure"
AND winlog.logon.type == "Network"
AND same source.ip + destination.ip + user.name
AND failed attempt count >= 3
AND within a 5 minute window
THEN:
Generate a Low Severity Alert: "Suspicious repeated failed logons"

Purpose: surface the pattern before the account locks, while there is
still time to investigate or block the source.

### Tier 2 — Lockout Confirmation (Medium Severity)

IF:
event.code == 4625
AND event.outcome == "failure"
AND winlog.logon.type == "Network"
AND same source.ip + destination.ip + user.name
AND failed attempt count >= 5
AND within a 60 second window
THEN:
Generate a Medium Severity Alert: "Account lockout threshold reached"

Purpose: confirms the AD lockout policy itself has (or is about to)
engage — this matches the native AD lockout threshold exactly, so it
functions as a correlation/confirmation signal rather than an early
warning. Useful for tracking which source IP triggered a real lockout,
for later blocking or correlation with other activity.

## Parameters

| Tier | Threshold | Window | Severity |
|---|---|---|---|
| Tier 1 — Early Warning | 3+ attempts | 5 minutes | Low |
| Tier 2 — Lockout Confirmation | 5+ attempts | 60 seconds | Medium |

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Brute Force | T1110 |

## Rationale
A legitimate user who mistypes a password typically fails once or
twice before succeeding or giving up. Three or more failed attempts
within five minutes already deviates from normal behavior; five or
more within one minute is consistent with automated credential-
guessing tools.

## Severity Reasoning
Originally this rule used a single High-severity tier at the
5-attempt threshold. On review, this threshold exactly matches the
AD account lockout policy — meaning the "detection" fired at the same
moment the account was already locked, which is confirmation after
the fact, not early warning. Splitting into two tiers fixes this:
Tier 1 gives an analyst time to act before lockout; Tier 2 confirms
the lockout event itself for tracking and correlation.

**Escalation note (future work):** either tier's severity should
increase if a failed-attempt burst is immediately followed by a
successful logon (event.code 4624) for the same account — this would
indicate the attack succeeded, not just that it was attempted. Not
implemented in this initial rule; see `investigation.md` for details.

## Related Files
- `query.json` — Elasticsearch aggregation query used to validate this rule
- `simulation.md` — How the attack was simulated for testing
- `investigation.md` — Evidence and findings from the test run
