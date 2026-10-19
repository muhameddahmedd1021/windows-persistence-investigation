# Registry Run key

The value `SOC-Lab-Run` was added under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. It starts PowerShell with the marker script and `-Case Registry` at the next sign-in of the same local account.

![Run value and command](../images/run-key.png)

## Investigation

![Splunk registry changes and execution](../images/splunk-run-key.png)

The [registry search](../splunk/searches/02-run-key-changes.spl) selects Sysmon event 13 and the case value name. It returned two rows, which refer to different objects: the Run command and a `RunNotification` DWORD. The second row is not another autostart command. The complete target path, value type and data are needed to distinguish them.

The Registry marker first appears after the restart and new interactive sign-in. Sysmon record 523 shows PowerShell launched by `C:\Windows\explorer.exe` as `MOHAMEDAHMED\mohamedahmed` at `2026-10-18T09:01:28.0632257Z`.

The configuration snapshot establishes the command in the value. The process event and resulting marker establish the observed execution after sign-in. Neither a writable path nor `ExecutionPolicy Bypass` is sufficient on its own to classify a command as malicious.

## Evidence

- [Registry configuration](../evidence/configuration/run-key.json)
- [Registry search results](../evidence/search-results/02-run-key-changes.csv)
- [Process results](../evidence/search-results/04-marker-execution.csv)
- [Registry marker](../evidence/markers/Registry.jsonl)
- [Native case events](../evidence/events/case-events.xml)

ATT&CK: T1547.001 — Registry Run Keys / Startup Folder.
