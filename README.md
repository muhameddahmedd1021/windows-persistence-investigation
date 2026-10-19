# Windows Persistence Investigation

Investigation of Scheduled Tasks, Registry Run keys and permanent WMI subscriptions in a Windows lab, using native event logs and Splunk.

The aim was to follow each persistence change from registration to execution, check whether it survived a restart, and verify removal by repeating its trigger. The cases used a local marker script so the resulting processes and artifacts could be examined without deploying malware.

![Splunk investigation dashboard](images/splunk-overview.png)

## Results

| Case | Execution observed | Restart test | After removal |
|---|---|---|---|
| Scheduled Task | PowerShell launched by `svchost.exe` | Executed at the next sign-in | No further marker |
| HKCU Run key | PowerShell launched by `explorer.exe` | Executed at the next sign-in | No further marker |
| WMI subscription | PowerShell launched by `WmiPrvSE.exe` as SYSTEM | Condition triggered execution after restart | No further marker |

A separate control task provided a known comparison for the task-registration searches. The broad search returned four registrations; a search limited to the Public case path returned one. This showed how a path condition changes coverage, rather than proving that other paths are safe.

## Investigation walkthrough

1. [Scheduled Task](docs/scheduled-task.md) — registration, action XML, creator and execution process.
2. [Registry Run key](docs/registry-run-key.md) — value data, logon execution and parent process.
3. [WMI subscription](docs/wmi-subscription.md) — filter, consumer, binding and SYSTEM execution.
4. [Restart and cleanup](docs/restart-and-cleanup.md) — execution across boots and the post-removal test.

Each page links the relevant Windows captures, SPL searches and exported results. The Dashboard Studio images were exported as PNG from Splunk using the indexed investigation data. [The evidence index](evidence/README.md) describes the included source records and configuration snapshots.

| Task action | Removal verification |
|---|---|
| [![Scheduled Task configuration](images/scheduled-task.png)](docs/scheduled-task.md) | [![Post-cleanup verification](images/cleanup.png)](docs/restart-and-cleanup.md) |

## Lab

| Component | Configuration |
|---|---|
| Endpoint | `MOHAMEDAHMED`, Windows Server 2022 Standard Evaluation |
| Account | Local account `mohamedahmed` |
| Telemetry | Security, Sysmon 15.22, PowerShell, Task Scheduler and WMI-Activity |
| SIEM | Splunk 9.4.1 on Ubuntu 24.04, `MOHAMED-SIEM` |
| Collection | Batch export of Windows evidence into `lab_persistence` |

Splunk indexed 2,314 records. Investigation searches select the 2,281 records whose native computer is `MOHAMEDAHMED`. The repository includes selected case events and the eight search-result exports, rather than a full machine-history export.

## Reproduce

[Setup and commands](docs/setup.md) cover telemetry, case registration, testing and removal in a disposable VM. The scripts in `windows/` provide repeatable case setup; the SPL files in `splunk/searches/` are the investigation searches.

The Windows endpoint is standalone. Results describe the controlled cases in this lab.

[Screenshot gallery](docs/screenshots.md) · [MIT license](LICENSE)
