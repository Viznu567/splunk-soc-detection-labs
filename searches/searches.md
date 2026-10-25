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

---

# Lab 2: Suspicious Account Activity

Data: Windows Security events 4720 (account created), 4732/4733 (added to / removed from a group) and 4726 (account deleted), generated on my own laptop with a test account (labtemp).

## D. Timeline of account changes

```
index=main source="*sample_account_changes.csv" | sort 0 _time, EventCode | table Time, EventCode, AffectedAccount, GroupName
```

## E. Account added to the Administrators group

```
index=main source="*sample_account_changes.csv" EventCode=4732 GroupName=Administrators | table _time, SubjectUserName, AffectedAccount, GroupName
```

## F. Account created, made admin and deleted within 5 minutes

```
index=main source="*sample_account_changes.csv"
| eval action=case(EventCode=4720,"created", EventCode=4732 AND GroupName="Administrators","added_to_admins", EventCode=4733 AND GroupName="Administrators","removed_from_admins", EventCode=4726,"deleted")
| where isnotnull(action)
| stats min(_time) as first_event, max(_time) as last_event, count(eval(action="created")) as created, count(eval(action="added_to_admins")) as admin_added, count(eval(action="deleted")) as deleted by AffectedAccount
| eval duration_sec=last_event-first_event
| where created>=1 AND admin_added>=1 AND duration_sec<=300
| eval first_event=strftime(first_event,"%Y-%m-%d %H:%M:%S"), last_event=strftime(last_event,"%Y-%m-%d %H:%M:%S")
| table AffectedAccount, first_event, last_event, duration_sec, created, admin_added, deleted
```

