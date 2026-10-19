# Lab setup

The recorded run used Windows Server 2022 Standard Evaluation, Windows PowerShell 5.1, Sysmon 15.22 and Splunk 9.4.1 on Ubuntu 24.04. The Windows endpoint was standalone, with a local account. Use disposable lab VMs and take a clean snapshot before changing auditing.

## Windows logging

Download [Sysmon from Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), check its Microsoft signature, and install the included configuration from an elevated PowerShell session:

```powershell
.\Sysmon64.exe -accepteula -i .\config\sysmon-lab.xml
.\windows\Invoke-Lab.ps1 -Phase Prepare
```

The preparation phase backs up audit settings, enables process command lines and PowerShell Script Block Logging, enables the Task Scheduler channel, and copies the marker script. The Sysmon configuration collects the process, registry, WMI and marker-file events needed by the cases.

`C:\ProgramData\SocPersistenceLab` holds run state, marker records and snapshots. `C:\Users\Public\SOC-Lab` holds the case script. Existing case object names are refused rather than overwritten.

## Register and test

```powershell
.\windows\Invoke-Lab.ps1 -Phase Install
.\windows\Invoke-Lab.ps1 -Phase Trigger
.\windows\Invoke-Lab.ps1 -Phase Snapshot -OutputDirectory C:\Lab\initial
```

`Install` registers the two tasks, HKCU Run value, and permanent WMI filter, consumer and binding. `Trigger` requests the Task and Control actions manually and starts `whoami.exe` for the WMI condition. It does not replace the logon test.

Restart Windows and sign in as the same local account. Start `whoami.exe` again. Compare the marker records with process events and the new boot time, then export the next snapshot:

```powershell
whoami.exe
.\windows\Invoke-Lab.ps1 -Phase Snapshot -OutputDirectory C:\Lab\after-restart
```

The marker script appends one local JSON record with the case, run ID, time, identity, process IDs, hostname and boot time. It does not download a payload or contact another machine.

## Splunk

Install `splunk/app` as the `soc_persistence` app in a lab Splunk instance before importing data. It defines the `lab_persistence` index, the `soc:windows:event` JSON sourcetype and four Dashboard Studio views: investigation overview, task registration and execution, registry changes, and WMI subscriptions.

Copy one final cumulative `events.jsonl` export to the Splunk host and import it with that index and sourcetype. Importing every cumulative snapshot would duplicate earlier records. Check the parsed `_time` against the source `utc` field before investigation.

The searches in `splunk/searches` select `computer="MOHAMEDAHMED"`. Change that filter and the dashboard filter when using a different endpoint name. Search over the time window of the recorded experiment, or use All time for a small isolated dataset.

For review using only this repository, import `evidence/events/case-events.jsonl`. It contains the 30 selected case records, not the complete original collection. Searches 01–07 can be compared with their included exports. The coverage search will describe the selected records rather than the original 2,281-record host collection.

## Remove and verify

```powershell
.\windows\Invoke-Lab.ps1 -Phase Cleanup
```

Save marker counts before the verification restart:

```powershell
$root='C:\ProgramData\SocPersistenceLab'
Get-ChildItem "$root\markers\*.jsonl" | ForEach-Object {
    [pscustomobject]@{case=$_.BaseName;count=@(Get-Content $_.FullName).Count}
} | ConvertTo-Json | Set-Content "$root\snapshots\marker-counts-before-clean-restart.json"
```

Restart, sign in, run `whoami.exe` and allow time for the consumer action. This run observed the endpoint for 100 seconds after the condition. Save the new counts as `marker-counts-after-clean-restart.json`. Confirm both that the named objects are absent and that counts have not increased.

```powershell
.\windows\Invoke-Lab.ps1 -Phase Snapshot -OutputDirectory C:\Lab\final
.\windows\Invoke-Lab.ps1 -Phase RestoreAuditing
```

Audit restoration applies the saved audit policy and the two saved registry settings. It does not uninstall Sysmon or reverse every monitoring change. Revert the clean VM snapshot when finished; do not use the restoration phase on a production endpoint.
