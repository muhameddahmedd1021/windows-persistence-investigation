# Scheduled Task

`SOC-Lab-GUI-Task` runs the marker script at sign-in for `SOC-WS01\Administrator`. It uses an interactive token, with the highest-privileges option left unchecked.

![Task principal and settings](../images/gui-task-general.jpg)

![Specific logon trigger](../images/gui-task-trigger.jpg)

The action starts `powershell.exe` with:

```text
-NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\SOC-Lab\Write-Marker.ps1" -Case Task
```

The complete [task XML](../evidence/gui-cases/task.xml) retains its action, principal, trigger and conditions.

## Execution

The task was requested once using Task Scheduler's Run action. It returned 0 and wrote a marker for PID 1136. After a restart and sign-in, the logon trigger produced PID 4004 and another marker. Both executions completed successfully in the task history.

![Task execution history](../images/gui-task-action-success.jpg)

The [lifecycle search](../splunk/searches/09-gui-task-lifecycle.spl) returns 14 records. The two event-201 rows contain return code 0. Security [4698 and 4699](../evidence/search-results/10-gui-task-security.csv) provide creation and deletion evidence.

## Action-path comparison

In the October 18 dataset, `SOC-Lab-Task` uses the Public copy of the marker script, while `SOC-Lab-Control` uses the ProgramData copy. The [broad registration search](../splunk/searches/01-task-registration.spl) returns both lab tasks and two Defender registrations. The [Public-path search](../splunk/searches/06-task-user-path.spl) returns one row.

The narrower match changes coverage; it does not establish that the other paths are safe. The original tasks were registered through PowerShell APIs, so an investigation should not depend on finding schtasks.exe in every creation chain. Original Sysmon records 241 and 480 identify the Task executions and their svchost.exe parent.

ATT&CK: T1053.005 — Scheduled Task.
