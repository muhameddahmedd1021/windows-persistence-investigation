# Scheduled Task

The task case, `SOC-Lab-Task`, launches PowerShell at sign-in for `mohamedahmed`. Its action points to `C:\Users\Public\SOC-Lab\Write-Marker.ps1 -Case Task`. A second task, `SOC-Lab-Control`, uses the ProgramData copy of the marker script as a known comparison.

## Registration

![Task action and execution principal](../images/scheduled-task.png)

Security event 4698 and [the task XML](../evidence/configuration/task.xml) provide the task name, trigger, principal and action. The task was registered through PowerShell APIs; an investigation cannot depend on finding `schtasks.exe` in every task-creation chain.

The configured run level is `Limited`. That setting alone is not a measurement of the resulting process integrity level.

## Search and execution

![Splunk task registration and execution](../images/splunk-scheduled-task.png)

The [registration search](../splunk/searches/01-task-registration.spl) returned four rows: the two lab tasks and two Windows Defender Scheduled Scan registrations. The Defender rows specify `MpCmdRun.exe` in their action XML; a familiar task name alone is insufficient to establish trust.

The [Public-path search](../splunk/searches/06-task-user-path.spl) returned only the case task. Its narrower result set is expected because the control task uses a different action path.

Sysmon process records 241 and 480 show the two Task marker launches. Their observed parent is `C:\Windows\System32\svchost.exe`. Correlating the command, case, account, process identifiers and marker time links the executions to the configured action. A registration record by itself does not establish execution.

## Evidence

- [Broad search results](../evidence/search-results/01-task-registration.csv)
- [Public-path search results](../evidence/search-results/06-task-user-path.csv)
- [Process results](../evidence/search-results/04-marker-execution.csv)
- [Task marker records](../evidence/markers/Task.jsonl)
- [Native case events](../evidence/events/case-events.xml)

ATT&CK: T1053.005 — Scheduled Task.
