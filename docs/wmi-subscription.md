# Permanent WMI subscription

The case uses a permanent subscription named `SOC-Lab-WMI` in `root\subscription`.

| Object | Role in this case |
|---|---|
| Event filter | Matches a `Win32_ProcessStartTrace` event for `whoami.exe` |
| Command-line consumer | Starts PowerShell with `Write-Marker.ps1 -Case WMI` |
| Binding | Connects the filter to the consumer |

The filter supplies the condition, the consumer supplies the action, and the binding connects them. When `whoami.exe` starts, WMI runs the consumer's PowerShell command. [Write-Marker.ps1](../windows/Write-Marker.ps1) only appends a local record containing the account, process ID, time and case label. It does not create the subscription.

![WMI filter, consumer and binding](../images/wmi-subscription.png)

## Registration and execution

![Splunk WMI object lifecycle and execution](../images/splunk-wmi.png)

The [WMI search](../splunk/searches/03-wmi-registration.spl) uses Sysmon events 19, 20 and 21. Its six result rows cover creation and deletion of the three objects. Checking the `Operation` field separates registration from removal.

Starting `whoami.exe` produced the first WMI marker. After restarting Windows, the same condition produced another marker. Sysmon records 249 and 554 show PowerShell launched by `C:\Windows\System32\wbem\WmiPrvSE.exe` as `NT AUTHORITY\SYSTEM`.

The creator account and later execution identity are different. The subscription was registered by the local lab account; the observed consumer action ran as SYSTEM. The marker and process records link that action to the tested condition.

To follow the case, read the filter's query, check the consumer's command, and confirm that the binding names those two objects. Then compare the marker with the PowerShell process event and its WmiPrvSE parent. The [setup page](setup.md#wmi-subscription) provides the three registration commands for reproducing the configuration.

## Removal

Cleanup removed the named binding, consumer and filter. An independent inventory found only the existing Windows SCM Event Log binding. Repeating `whoami.exe` after the cleanup restart produced no additional WMI marker.

## Evidence

- [Filter configuration](../evidence/configuration/wmi-filter.json)
- [WMI search results](../evidence/search-results/03-wmi-registration.csv)
- [Execution process results](../evidence/search-results/04-marker-execution.csv)
- [WMI markers](../evidence/markers/WMI.jsonl)
- [Remaining bindings](../evidence/configuration/cleanup-wmi-bindings.json)

ATT&CK: T1546.003 — WMI Event Subscription.
