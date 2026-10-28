# Lab setup and reproduction

Use an isolated Windows Server lab with Windows PowerShell 5.1, Sysmon and Splunk. Work with a dedicated lab account and preserve existing evidence before reusing object names.

## Logging and marker

Install [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) using [config/sysmon-lab.xml](../config/sysmon-lab.xml). Sysmon installation and configuration use its command-line interface. Check the Microsoft signature before installation.

In Local Security Policy, enable successful Process Creation and Other Object Access Events auditing. In Local Group Policy, enable process command-line inclusion and PowerShell Script Block Logging. Enable the Task Scheduler Operational channel in Event Viewer. Check that Security 4698/4699, Sysmon process/registry/WMI events and the task execution channel are available before running cases.

Using File Explorer, create `C:\Users\Public\SOC-Lab` and `C:\ProgramData\SocPersistenceLab\markers`. Copy [Write-Marker.ps1](../windows/Write-Marker.ps1) into the Public folder. Using Notepad, create `C:\ProgramData\SocPersistenceLab\state.json` with a run label:

```json
{"run_id":"persistence-lab"}
```

The account running the cases needs write access to its lab marker folder. Inspect that folder's Security tab rather than assuming a scheduled action will have an elevated token. The published walkthrough used the existing local Administrator account.

## Scheduled Task

1. Open Task Scheduler and choose Create Task. Use `SOC-Lab-GUI-Task` and the current local lab account. Select Run only when user is logged on and leave highest privileges unchecked.
2. Add an At log on trigger for that account.
3. Add a Start a program action for `powershell.exe`, with the arguments shown in the [Task walkthrough](scheduled-task.md).
4. Save the task. Select it and use Run once; inspect History, the resulting marker and native process records.

## Run value

Open Registry Editor at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Create a String Value named `SOC-Lab-GUI-Run` and enter the command in [run-value.json](../evidence/gui-cases/run-value.json). Confirm the real value name, type and data before testing.

Restart Windows and sign in with the same account. Compare the Task and Registry markers, parent processes and boot time. Do not count a configured trigger as a completed execution.

## WMI subscription

The recorded WMI case uses the three objects documented in [the WMI walkthrough](wmi-subscription.md). To reproduce that configuration, open Windows PowerShell as a lab administrator and create the filter, consumer and binding with the commands below.

First, select Windows PowerShell as the action executable and create a filter that watches for `whoami.exe`:

```powershell
$exe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$filter=Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='SOC-Lab-WMI';EventNamespace='root\cimv2';QueryLanguage='WQL';Query="SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'whoami.exe'"}
```

Next, create the consumer. Its action runs the local marker script with the WMI case label:

```powershell
$consumer=Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='SOC-Lab-WMI';ExecutablePath=$exe;CommandLineTemplate=('"'+$exe+'" -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\SOC-Lab\Write-Marker.ps1" -Case WMI')}
```

Finally, bind that filter to that consumer:

```powershell
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter;Consumer=$consumer}
```

Run `whoami.exe` once to exercise the condition. Check the resulting WMI marker and WmiPrvSE-to-PowerShell chain. Restart and repeat the condition once to test persistence.

## Collect and search

The October 27 walkthrough forwards Windows XML into `lab_windows` using sourcetype `soc:windows:xml`. Searches 09–13 use the native field names available in that collection. In the recorded configuration, the Run-value search uses the name in the raw XML; full TargetObject and Details remain in the source records.

The included Splunk app defines `lab_persistence`, the JSON sourcetype `soc:windows:event` and four Dashboard Studio views for the October 18 collection. For a repository-only review, import [case-events.jsonl](../evidence/events/case-events.jsonl). It contains 30 selected records. Searches 01–07 match that selection; search 08 then reports the smaller imported collection rather than the original 2,281-record host dataset.

Use All time for these small recorded datasets and check event timestamps against source UTC. Preserve source channel and record IDs when exporting evidence. Import a cumulative capture only once to avoid duplicate events.

## Remove and verify

Delete only the named test task in Task Scheduler and the named test value in Registry Editor. For WMI, remove its named binding first, then its consumer and filter through the WMI interface. Preserve object definitions and marker records.

Restart, sign in and repeat the applicable trigger. Compare marker hashes and process events with the values recorded before removal. The [verification page](restart-and-cleanup.md) describes the observed results.
