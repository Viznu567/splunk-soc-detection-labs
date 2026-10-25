\# Splunk Lab: Detecting a Brute-Force Login in Windows Security Logs



A small SOC-style lab where I generate failed and successful Windows logins on my own machine, load the logs into Splunk, and write a search that detects a brute-force pattern: many failed logins followed by a success on the same account.



\## Environment

\- Windows 11 laptop (own machine, lab only)

\- Splunk Enterprise (Free license)

\- Data: Windows Security events 4625 (failed logon) and 4624 (successful logon)



\## What I did

1\. Created a local test account (`labuser`) so my real account was never at risk.

2\. Made 8 failed network logins with wrong passwords, then one successful login.

3\. Exported the Security events with PowerShell to CSV and uploaded them to Splunk.

4\. Wrote three searches (see `searches/searches.md`) and saved the detection as a Splunk report.



\## Detection logic

Alert when a successful logon (4624) happens after 5 or more failed logons (4625) on the same account within 5 minutes. The search uses `streamstats` with a 5-minute window per account.



\## Results

\- 8 failed logons (4625) on `labuser`, SubStatus `0xc000006a` (valid username, wrong password), LogonType 3 (network)

\- 1 successful logon (4624) on the same account shortly after

\- The detection returned exactly one row: `labuser`, 8 failures before the success



Screenshots are in `screenshots/`:

\- `01\_event\_counts.png`: event counts by EventCode

\- `02\_failed\_logins.png`: failed logins in detail

\- `03\_bruteforce\_detection.png`: detection result

\- `04\_saved\_report.png`: saved Splunk report



\## MITRE ATT\&CK mapping

| Observation | Technique |

|---|---|

| Repeated failed logins with wrong passwords | T1110.001 Brute Force: Password Guessing |

| Successful login after the failures | T1078.003 Valid Accounts: Local Accounts |



\## Limitations (honest notes)

\- This is a simulation. The source address is `::1` (localhost), not a remote attacker.

\- The threshold (5 failures in 5 minutes) is an example I chose, not a tuned value. In a real environment it would need tuning against normal activity, such as users mistyping passwords.

\- Splunk Free does not support alerting, so the detection is saved as a report instead of an alert.

\- Hostname is masked as `LAB-PC` and only the lab account's events are included in the sample data.



\## What I would add next

\- Detect the same pattern from multiple source IPs

\- Add a dashboard with failed logins over time

\- Send the detection output to a ticket or case template

