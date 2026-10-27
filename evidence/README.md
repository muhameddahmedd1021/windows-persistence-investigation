# Evidence index

| Collection | Source | Included evidence |
| --- | --- | --- |
| October 18 | `MOHAMEDAHMED`, standalone local-account lab | 30 selected native events, configuration snapshots and seven marker records |
| October 27 | `SOC-WS01`, local Administrator on the domain lab endpoint | 28 native events, Task and Run configuration, three marker records and cleanup verification |

All event times are UTC. Individual Windows XML events retain their source text, channel and record ID.

## October 18

- [Original event XML](events/case-events.xml) and [normalized JSONL](events/case-events.jsonl)
- [Selection and event hashes](events/selection.json)
- [Configuration](configuration/) and [original marker files](markers/)
- Searches 01–08 in [search-results](search-results/)

The complete original collection has 2,314 records, of which 2,281 identify the native host as MOHAMEDAHMED. The coverage CSV describes that host-scoped collection. The repository's 30 events are the case selection, not a full machine-history export. The collection run label is metadata added during normalization, not a Windows event field.

## October 27

- [Native XML](gui-cases/events.xml) and [normalized JSONL](gui-cases/events.jsonl)
- [Selection and individual event hashes](gui-cases/selection.json)
- [Task XML](gui-cases/task.xml) and [Run value](gui-cases/run-value.json)
- [New marker records](gui-cases/markers.jsonl) and [cleanup check](gui-cases/cleanup.json)
- Searches 09–13 in [search-results](search-results/)

The selected XML includes the confirmed interactive sign-in used for the final cleanup check. The three marker records are two Task executions and one Registry execution. The original marker files are preserved unchanged in the October 18 evidence folder.

The [search guide](../docs/search-guide.md) links every query to its completed result table and screenshot. Windows images show the actual Task Scheduler and Registry Editor interfaces. The WMI object inspection uses the Windows PowerShell WMI interface.

`SHA256SUMS` covers the published files.
