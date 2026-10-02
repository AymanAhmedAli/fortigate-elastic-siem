# Simulation — Failed Login Brute Force

## Objective
Generate realistic repeated-failed-login traffic against the Windows
Domain Controller to validate Rule 2 (Brute Force Detection).

## Environment
- Attacker: Kali Linux (172.18.183.50)
- Target: Windows Server 2022 DC (172.18.183.10, test.local)
- Protocol: Kerberos (port 88)

## Prerequisite — AD Account State Issues
Two account-state issues on the `ayman.ahmed` test account had to be
resolved before authentication attempts (even failed ones) would
reach the DC correctly:

1. **Account expiration date in the past** — the account had an
   `AccountExpirationDate` set from an earlier test, which had
   already elapsed. This caused `kinit` to fail with "Client's
   credentials have been revoked" regardless of password correctness.
   Fixed with:
```powershell
   Clear-ADAccountExpiration -Identity "ayman.ahmed"
```

2. **Kerberos client not installed on Kali** — `kinit` was not
   present by default. Installed with:
```bash
   sudo apt install krb5-user -y
```
   and configured `/etc/krb5.conf` to point directly at the DC
   (`kdc = 172.18.183.10`), since the lab has no DNS SRV records
   for Kerberos realm discovery.

## Attack Commands

```bash
for i in 1 2 3 4 5 6; do
  echo "wrongpass$i" | kinit ayman.ahmed@TEST.LOCAL
  echo "---"
done
```

## Result
- Attempts 1-5: `kinit: Password incorrect while getting initial
  credentials`
- Attempt 6: `kinit: Client's credentials have been revoked` — the
  account's lockout threshold (5 attempts, consistent with the AD
  Security Hardening policy documented elsewhere in this portfolio)
  triggered an automatic lockout after the 5th failure.

Each failed attempt generated a corresponding Event ID 4625 on the
DC, picked up by Winlogbeat and indexed in Elasticsearch within
seconds.

See `investigation.md` for the resulting evidence and analysis.
