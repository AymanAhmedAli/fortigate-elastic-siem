# Troubleshooting Notes — Brute Force Detection Validation

This file records the infrastructure, telemetry, and detection-engineering issues encountered while validating the current Windows failed-logon detection scenario.

## 1. No fresh Windows logs in Elastic

The first problem was not the detection rule. Discover showed no fresh Winlogbeat data.

Checks confirmed that the Winlogbeat service was running, and later logs showed a successful connection to Elasticsearch with acknowledged events. Once fresh Domain Controller events appeared in Elasticsearch, detection testing could continue.

**Lesson:** validate the full telemetry path before changing rule logic:

```text
Windows Event Log → Winlogbeat → Elasticsearch → Kibana
```

## 2. Domain Controller instability

The Windows Server VM experienced repeated unexpected restarts. System logs showed:

```text
Event 41   Microsoft-Windows-Kernel-Power
Event 6008 Previous shutdown was unexpected
```

Windows Error Reporting also recorded bugcheck `0x00000124` and created `C:\Windows\MEMORY.DMP`.

No matching WHEA-Logger entries were found during the checks performed on either the guest or physical host. The evidence therefore proved a real crash, but did not prove that guest RAM exhaustion alone was the root cause.

**Lesson:** keep infrastructure stability separate from detection-rule troubleshooting.

## 3. Ubuntu disk exhaustion

Ubuntu became extremely slow and Kibana queries timed out. Disk inspection showed the root filesystem at approximately 98% usage:

```text
~49 GB total
~46 GB used
~1.4 GB available
```

Directory analysis identified the largest consumers:

```text
/var        ≈ 25 GB
/var/ossec  ≈ 12 GB
/var/lib    ≈ 9.4 GB
/var/log    ≈ 2.2 GB
```

The largest single area was:

```text
/var/ossec/queue/vd/feed ≈ 11 GB
```

This was Wazuh Vulnerability Detection feed data. Elasticsearch data itself was under 1 GB at the time, so Elasticsearch was not the main disk consumer.

### Remediation
The Wazuh data was retained. The Ubuntu virtual disk was expanded from about 50 GB to 100 GB, then the root partition/filesystem was expanded. Final root usage was approximately:

```text
~99 GB total
~45–46 GB used
~49 GB available
~49% used
```

**Lesson:** do not assume SIEM index data is the largest consumer; inspect the filesystem before deleting anything.

## 4. Ubuntu memory pressure

Ubuntu originally had 8 GB RAM while running Elasticsearch, Kibana, Logstash, Wazuh components, GNOME, and other services. Swap usage was high enough to contribute to noticeable sluggishness.

Ubuntu was increased to 10 GB. Wazuh services were stopped/disabled while working on the Elastic project so unrelated components would not compete for memory and CPU.

After the RAM increase, Elasticsearch auto-sized its heap to approximately 4.8 GB, which was still too aggressive for a 10 GB multi-service lab VM.

### Elasticsearch heap tuning
An override under `/etc/elasticsearch/jvm.options.d/` set:

```text
-Xms3g
-Xmx3g
```

After restart, Elasticsearch showed the expected 3 GB heap. During the follow-up check, available RAM improved to roughly 3.5 GiB and swap usage dropped to about 21 MiB.

**Lesson:** increasing VM RAM can cause Elasticsearch auto-sizing to consume the extra memory. Measure and tune the heap for the actual lab workload.

## 5. Elasticsearch and Kibana health

Elasticsearch HTTPS on port 9200 returned the expected unauthenticated `401 security_exception`, proving the service and TLS endpoint were responding.

Kibana was verified successfully on the lab HTTP endpoint at port 5601.

## 6. Authentication attempts were slower than expected

A single failed SMB authentication attempt sometimes took roughly 15–21 seconds to return. Port 445 itself was reachable, and there were no existing SMB sessions on the Windows Client.

This timing mattered because multiple sequential failures could span more than one minute, causing a narrow rule look-back window to split the events across separate executions.

**Lesson:** detection windows must match observed event timing, not assumed timing.

## 7. Hostname vs IP changed authentication behavior

Testing by Domain Controller hostname did not consistently increase `badPwdCount` once per command and was not reliable for the intended NTLM/Event 4625 validation.

Testing by the DC IP produced the expected fields:

```text
event.code = 4625
source.ip = 10.10.10.30
winlog.event_data.LogonType = 3
winlog.event_data.AuthenticationPackageName = NTLM
```

The AD account state was checked after attempts using `badPwdCount` and `LockedOut` to confirm the number of effective failures and avoid reaching the lockout threshold unintentionally.

**Lesson:** the number of commands entered is not the source of truth; validate the resulting authentication events and AD account state.

## 8. Rule tuning

The active rule groups Event ID 4625 network logons by source IP and target username and alerts at 4 effective failures. The AD account lockout threshold is 5, so this creates an early-warning signal before lockout.

The rule executes every minute. The additional look-back was widened during validation after observed authentication delays showed that a narrow window could miss the complete sequence.

## 9. Alert existed but the UI showed the wrong time range

After the rule finally generated an alert, the Security Alerts page initially appeared empty because its time picker was showing an older range.

Changing the Alerts time range to `Last 15 minutes` and refreshing revealed the successful alert:

```text
Possible Brute Force - Failed Logons
Severity: Medium
Risk score: 47
Source: 10.10.10.30
```

**Lesson:** before concluding that a rule failed, verify the Alerts UI time picker as well as the rule and source events.

## Final Troubleshooting Sequence

```text
1. Check infrastructure stability
2. Check disk and memory headroom
3. Verify Elasticsearch and Kibana
4. Verify Winlogbeat connectivity
5. Generate one controlled failed logon
6. Verify Event 4625 on the DC
7. Verify the same event in Elastic
8. Confirm source.ip, target username, and LogonType
9. Confirm AD badPwdCount before generating more failures
10. Generate only enough effective failures to meet the detection threshold
11. Verify the rule execution/look-back window
12. Verify the Security Alerts time range
```

The main project lesson was that reliable detection engineering depends on reliable infrastructure and telemetry. The rule should only be blamed after the source event, shipping pipeline, index, execution window, and UI time range have all been verified.
