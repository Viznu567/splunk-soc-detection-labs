\# Splunk Lab: Searches



Data: Windows Security events (4624 and 4625) exported from my own laptop, with 8 failed logins on a test account (labuser) followed by one successful login.



\## A. Event counts by EventCode



```

index=main source="\*windows\_security\_events.csv" | stats count by EventCode

```



\## B. Failed logins in detail



```

index=main source="\*windows\_security\_events.csv" EventCode=4625 | stats count, earliest(Time) as first\_attempt, latest(Time) as last\_attempt by TargetUserName, IpAddress, LogonType, SubStatus

```



\## C. Brute force followed by a successful login



```

index=main source="\*windows\_security\_events.csv" (EventCode=4625 OR EventCode=4624)

| sort 0 \_time

| streamstats time\_window=5m count(eval(EventCode=4625)) as failed\_logins\_5m by TargetUserName

| where EventCode=4624 AND failed\_logins\_5m>=5

| table \_time, TargetUserName, failed\_logins\_5m, LogonType, IpAddress, Computer

```

