# Splunk SOC Detection Labs: Windows Security Logs

Two small, hands-on SOC-style labs. In each one I generate real Windows Security events on my own machine, load them into Splunk, and write a search that detects a suspicious pattern. Both detections are saved as Splunk reports and mapped to MITRE ATT&CK.

| Lab | Scenario | Key events | Detection |
|---|---|---|---|
| 1 | Brute-force login | 4625 (failed logon), 4624 (successful logon) | Successful logon after 5+ failures on the same account within 5 minutes |
| 2 | Suspicious account activity | 4720 (account created), 4732/4733 (group member added/removed), 4726 (account deleted) | Account created, added to Administrators and deleted within 5 minutes |

## Environment
- Windows 11 laptop (own machine, lab use only)
- Splunk Enterprise (Free license)
- PowerShell for generating and exporting events
- Test accounts only (`labuser`, `labtemp`); my real account was never used

## Repo layout
- `data/`: sanitized sample events (CSV)
- `searches/searches.md`: all SPL searches, labelled A to F
- `screenshots/`: results, numbered 01 to 08

---

## Lab 1: Brute-force login detection

**What I did**
1. Created a local test account (`labuser`).
2. Made 8 failed network logins with wrong passwords, then one successful login.
3. Exported events 4624 and 4625 with PowerShell to CSV and uploaded them to Splunk.
4. Wrote searches A to C and saved the detection (C) as a report.

**Detection logic:** alert when a successful logon (4624) follows 5 or more failed logons (4625) on the same account within 5 minutes, using `streamstats` with a 5-minute window per account.

**Result**
- 8 failed logons on `labuser`, SubStatus `0xc000006a` (valid username, wrong password), LogonType 3 (network)
- 1 successful logon on the same account shortly after
- The detection returned exactly one row: `labuser`, 8 failures before the success

**Screenshots:** `01_event_counts.png`, `02_failed_logins.png`, `03_bruteforce_detection.png`, `04_saved_report.png`

## Lab 2: Suspicious account activity

**What I did**
1. Checked that Windows was auditing User Account Management and Security Group Management.
2. Created a test account (`labtemp`), added it to the local Administrators group, removed it, and deleted it, with a few seconds between each step.
3. Exported events 4720, 4732, 4733 and 4726 with PowerShell, resolved the account names, and uploaded the sample to Splunk.
4. Wrote searches D to F and saved the detection (F) as a report.

**Detection logic:** per account, find a creation (4720), an addition to the Administrators group (4732) and a deletion (4726) within 300 seconds of each other. Short-lived accounts that gain admin rights are a common pattern for hidden persistence.

**Result**
- Timeline of 6 events from creation to deletion
- `lab-admin` added `labtemp` to Administrators at 15:00:52
- The detection returned one row: `labtemp`, created 1, admin added 1, deleted 1, over 15 seconds

**Screenshots:** `05_account_timeline.png`, `06_admin_added.png`, `07_account_lifecycle_detection.png`, `08_saved_report_lab2.png`

---

## MITRE ATT&CK mapping
| Observation | Technique |
|---|---|
| Repeated failed logins with wrong passwords (Lab 1) | T1110.001 Brute Force: Password Guessing |
| Successful login after the failures (Lab 1) | T1078.003 Valid Accounts: Local Accounts |
| New local account created (Lab 2) | T1136.001 Create Account: Local Account |
| Account added to the Administrators group (Lab 2) | T1098 Account Manipulation |

The deletion of the account in Lab 2 is part of the detection pattern, but I did not map it to a technique.

## Limitations (honest notes)
- Both labs are simulations on one machine. The source of the logins is `::1` (localhost), not a remote attacker.
- Thresholds (5 failures in 5 minutes, 5 minutes for the account lifecycle) are examples I chose, not tuned values. In a real environment they would need tuning against normal activity, such as users mistyping passwords or admins creating temporary accounts.
- The sample data is tiny (9 events in Lab 1, 6 in Lab 2), so these labs show the detection logic, not performance at scale.
- Splunk Free does not support alerting, so the detections are saved as reports instead of alerts.
- Hostnames are masked as `LAB-PC`, the admin account as `lab-admin`, and only the events for the lab accounts are included.

## What I would add next
- A dashboard of failed logins and account changes over time
- Detection of the same pattern from multiple source IPs
- Process creation events (4688) to see what ran after an account change