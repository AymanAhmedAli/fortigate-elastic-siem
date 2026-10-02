# Investigation — Failed Login Brute Force Detection

## Summary
Validated Rule 2 (Brute Force Detection) against real failed
authentication attempts generated via Kerberos against the Windows
Domain Controller, captured by Winlogbeat and indexed in
Elasticsearch. The detection logic correctly groups failed attempts
by source IP, destination IP, and target username, and the observed
volume clearly exceeds the detection threshold.

## Evidence

### Raw Event Sample
A single logged failed-authentication event (Event ID 4625), as
captured by Winlogbeat:

event.code: 4625
event.action: logon-failed
event.outcome: failure
winlog.logon.type: Network
source.ip: 172.18.183.50
source.domain: KALI
user.name: ayman.ahmed
user.domain: WORKGROUP
winlog.logon.failure.reason: Unknown user name or bad password.
winlog.computer_name: DomainController.test.local


All six attempts share the same `source.ip` (172.18.183.50) and
`user.name` (ayman.ahmed), occurring within a single second
(12:07:09.414 to 12:07:09.608) — the exact signature described in
`rule.md`.

### Aggregation Query Result
Query from `query.json`, run against the last 60 seconds of traffic
at the time of testing:

| source.ip | user.name | failed attempts |
|---|---|---|
| **172.18.183.50** | **ayman.ahmed** | **6** |
| 172.18.183.50 | administrator | 6 (from an earlier, separate test run) |

### Finding
The attacking host generated 6 failed authentication attempts against
a single account within approximately 0.2 seconds — well above Tier
2's 5-attempt / 60-second threshold. The AD account lockout policy
(threshold: 5) triggered automatically on the 6th attempt, confirming
Tier 2's threshold choice and the underlying AD hardening
configuration (documented separately in the `powershell-scripts` AD
hardening project) are working as designed.

## Root Cause Notes (Pipeline Debugging)
Three issues had to be resolved before this traffic was visible at
all — documented here for anyone reproducing this lab:

1. **Winlogbeat using a stale Elasticsearch password** — after an
   Elasticsearch password reset (needed to recover access following
   an unrelated outage), Winlogbeat on the DC was still configured
   with the old password and had stopped shipping events since
   September 6th. Fixed by updating `winlogbeat.yml` and restarting
   the service.
2. **Target test account had an expired `AccountExpirationDate`** —
   left over from an earlier test, this caused every authentication
   attempt (even with a correct password) to fail with "credentials
   revoked" rather than a normal bad-password error. Cleared with
   `Clear-ADAccountExpiration`.
3. **No Kerberos client on the attacking host** — `kinit` had to be
   installed and `/etc/krb5.conf` manually pointed at the DC's IP,
   since the lab has no DNS-based Kerberos realm discovery
   configured.
4. **Network interruption during review fixes** — while updating
   this rule's severity tiers, all outbound TCP connections from the
   Ubuntu host (git push, curl) began timing out. Root cause: kesl
   (Kaspersky Endpoint Security for Linux) was injecting netfilter
   rules across all nftables tables (nat, filter, mangle, raw),
   blocking outbound TCP connections. Service was stopped and
   disabled permanently via systemctl (confirmed: disabled,
   inactive/dead) — will not restart on reboot. Rebooted to flush
   residual kernel-level rules after disabling.

## Conclusion
The attacking host generated 6 failed authentication attempts within
approximately 0.2 seconds — exceeding Tier 2's threshold (5 attempts
/ 60 seconds) and triggering the AD account lockout policy on the
6th attempt, confirming both thresholds align.

**Design note from review:** the original single-tier design (High
severity at 5 attempts) was reviewed and found to be a confirmation
signal, not an early warning — since 5 attempts is also the AD
lockout threshold, the alert would fire at the exact moment the
account was already locked. This was split into two tiers (see
`rule.md`): Tier 1 (3 attempts / 5 min, Low severity) now gives an
analyst a window to act before lockout; Tier 2 (5 attempts / 60 sec,
Medium severity) confirms the lockout event itself for tracking and
correlation. This test run validated Tier 2 directly; Tier 1 has not
yet been tested against a slower attack pattern (see Next Steps).

## Next Steps
- [ ] Implement the severity escalation noted in `rule.md`: raise to
      Critical if a failed-attempt burst is immediately followed by a
      successful logon (event.code 4624) for the same account
- [ ] Build the equivalent rule in Kibana's Detection Engine for
      real-time alerting
- [ ] Define Rule 3 — Password Spraying (same password, multiple
      usernames) as a separate, related detection
- [ ] Test against a slower/distributed brute force pattern to check
      whether the 60-second window still catches a throttled attack
- [ ] Test Tier 1 specifically with a throttled attack (e.g. 3-4
      failed attempts spread over 2-3 minutes) to confirm it fires
      before lockout, not just alongside Tier 2
