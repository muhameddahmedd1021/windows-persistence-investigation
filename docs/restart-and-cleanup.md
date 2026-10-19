# Restart and cleanup verification

Registration, execution and persistence were checked as separate stages. The marker script records the account, process IDs, UTC time and last boot time whenever a case action runs.

## Initial execution

The Task and Control cases were requested manually first. Starting `whoami.exe` generated the WMI condition. The Run value required a new sign-in and therefore has no initial marker.

![Initial marker records](../images/execution-before-restart.png)

## After restart

Windows restarted from the initial boot at `08:19:04.5000000Z` to a new boot at `08:58:23.5000000Z` on 18 October 2026. A new sign-in exercised the task and Run triggers; another `whoami.exe` exercised the WMI condition.

![Case execution across boot times](../images/execution-after-restart.png)

The [process search](../splunk/searches/04-marker-execution.spl) returned seven launches. Security 4688 provides a second process-creation source for comparison. PID correlation requires the host and time because a PID can be reused; Sysmon ProcessGuid gives a more precise process identifier.

## After removal

The two tasks, Run value, and WMI binding, consumer and filter were removed. Windows restarted again, with a boot time of `09:29:17.500000Z`, later than cleanup at `09:28:35.5177445Z`. Sign-in and the WMI condition were repeated, followed by a 100-second observation interval.

![Objects absent and counts unchanged](../images/cleanup.png)

| Case | Before verification restart | After repeated trigger |
|---|---:|---:|
| Task | 2 | 2 |
| Registry | 1 | 1 |
| WMI | 2 | 2 |
| Control | 2 | 2 |

The named objects were absent and marker counts stayed unchanged. This supports successful removal of the tested mechanisms under these triggers. It is not a claim that every possible persistence location on the endpoint was examined.

## Evidence

- [Marker records](../evidence/markers)
- [Sysmon process results](../evidence/search-results/04-marker-execution.csv)
- [Security 4688 results](../evidence/search-results/07-process-creation-security.csv)
- [Object checks](../evidence/configuration/cleanup.json)
- [Counts before](../evidence/configuration/marker-counts-before-clean-restart.json) and [after](../evidence/configuration/marker-counts-after-clean-restart.json)
