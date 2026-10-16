# Brute Force Detection — Current Validated Scenario

## Status
**Validated end-to-end on 2026-10-16.**

This detection is implemented in Kibana Detection Engine and successfully generated a real alert from Windows failed-logon telemetry.

## Objective
Detect repeated Windows network logon failures from the same source IP against the same target account before the Active Directory account lockout threshold is reached.

## Current Lab Path

```text
Windows Client 10.10.10.30
        |
        | SMB authentication attempts
        v
Windows Server 2022 Domain Controller 10.10.10.10
        |
        | Security Event ID 4625
        v
Winlogbeat 8.19.21
        |
        v
Elasticsearch 8.19.21
        |
        v
Kibana Detection Engine
        |
        v
Possible Brute Force - Failed Logons
```

## Active Directory Policy

| Setting | Value |
|---|---:|
| Account lockout threshold | 5 failed attempts |
| Lockout duration | 30 minutes |
| Observation window | 30 minutes |

The detection threshold is intentionally set to **4**, one event below the AD lockout threshold. The goal is to create an early warning before the fifth failure locks the account.

## Detection Rule

| Setting | Value |
|---|---|
| Name | `Possible Brute Force - Failed Logons` |
| Rule type | Threshold |
| Index | `winlogbeat-*` |
| Query | `event.code: "4625" AND winlog.event_data.LogonType: "3"` |
| Group by | `source.ip`, `winlog.event_data.TargetUserName` |
| Threshold | `>= 4` |
| Count | All results |
| Severity | Medium |
| Risk score | 47 |
| Runs every | 1 minute |
| Additional look-back | tuned to cover the observed authentication delay; final validation used a wider look-back than the initial 2-minute setting |
| Actions | None |

## Why Event 4625 + Logon Type 3?
- **4625** = failed logon.
- **Logon Type 3** = network logon.
- The successful test used SMB authentication to the DC and produced NTLM network-logon failures.

Validated event fields:

```text
event.code: 4625
source.ip: 10.10.10.30
winlog.event_data.LogonType: 3
winlog.event_data.AuthenticationPackageName: NTLM
winlog.event_data.TargetUserName: brutetest4 / brutetest5
```

## Attack Simulation
A clean test account was created and checked before use:

```powershell
Get-ADUser brutetest5 -Properties badPwdCount,LockedOut |
Select-Object SamAccountName,badPwdCount,LockedOut
```

Expected baseline:

```text
badPwdCount = 0
LockedOut   = False
```

From the Windows Client, failed SMB authentication attempts were generated against the DC by IP:

```cmd
net use \\10.10.10.10\IPC$ /user:test.local\brutetest5 WrongPassword
```

The command returned:

```text
System error 1326 has occurred.
The user name or password is incorrect.
```

Only four effective failures were used for the final test. No fifth attempt was generated because the AD lockout threshold is 5.

Final account state:

```text
badPwdCount = 4
LockedOut   = False
```

## Validation Evidence
Four Event ID 4625 documents were visible in Elastic for a clean test sequence. The Detection Engine then generated one Medium-severity alert:

```text
Rule: Possible Brute Force - Failed Logons
Severity: Medium
Risk score: 47
Source: 10.10.10.30
Alert count: 1
```

This proves the full path worked:

```text
Failed authentication
→ Windows Security Event 4625
→ Winlogbeat
→ Elasticsearch
→ Kibana threshold rule
→ Security alert
```

## Important Test Finding — Use the IP Path
Testing with the DC hostname was not reliable for this specific 4625/NTLM validation:

```cmd
net use \\DomainController\IPC$ ...
```

It changed the authentication behavior and did not consistently produce the same effective bad-password events. The validated path was:

```cmd
net use \\10.10.10.10\IPC$ ...
```

Using the IP produced the expected NTLM network logon failure with `source.ip = 10.10.10.30` and `LogonType = 3`.

## Detection Engineering Lessons
1. **Validate telemetry before debugging the rule.** A perfect rule cannot alert if fresh Winlogbeat data is not reaching Elasticsearch.
2. **Count effective authentication failures, not commands typed.** `badPwdCount` and DC Security events are the source of truth.
3. **Authentication method matters.** Hostname and IP access can follow different authentication paths.
4. **Detection windows must match real timing.** SMB failures took roughly 15–21 seconds during testing, so a narrow look-back could split the events across executions.
5. **Alert before lockout.** Threshold 4 was chosen because AD locks the account at 5.
6. **Check the Alerts time picker.** The alert existed but was initially hidden because the Security Alerts page was showing an older time range.

## Infrastructure Issues Encountered During Validation
The rule test exposed several infrastructure problems that had to be solved before the result could be trusted:

- Windows Server VM experienced repeated unexpected restarts (`Kernel-Power 41`, `EventLog 6008`) and one recorded bugcheck `0x124`.
- Winlogbeat telemetry was temporarily unavailable after the instability.
- Ubuntu root filesystem reached **98% usage**.
- `/var/ossec/queue/vd/feed` consumed approximately **11 GB** of the original ~50 GB Ubuntu disk.
- Ubuntu virtual disk was expanded to **100 GB** and the root filesystem expanded to ~99 GB, reducing usage to ~49%.
- Ubuntu RAM was increased from 8 GB to 10 GB.
- Wazuh services were stopped/disabled while working on the Elastic project so the unrelated Wazuh stack did not compete for resources.
- Elasticsearch auto-sized its heap to about 4.8 GB after the RAM increase; it was overridden to `-Xms3g -Xmx3g` for this lab.
- After tuning, available RAM increased and swap usage dropped from hundreds of MB to approximately 21 MB during the check.
- Elasticsearch HTTPS health was confirmed by the expected unauthenticated `401` response on `https://localhost:9200`.
- Kibana was verified on `http://10.10.10.20:5601`.

These issues are part of the project evidence because they demonstrate that detection engineering depends on stable infrastructure and reliable telemetry.

## Next Steps
- Investigate false positives such as legitimate password mistakes or stale stored credentials.
- Add severity escalation when repeated 4625 failures are followed by a successful 4624 for the same account.
- Build the next scenario: **Password Spraying**.
- Add screenshots/evidence to the repository without exposing credentials or secrets.

## Historical Material
The older files in this directory (`simulation.md`, `investigation.md`, and earlier query material) contain evidence from the previous topology and are retained as historical project records. This README describes the **current validated lab implementation**.
