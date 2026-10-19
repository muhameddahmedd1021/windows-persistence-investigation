# Evidence index

The recorded experiment ran on `MOHAMEDAHMED` on 18 October 2026. Timestamps in the event files and investigation text are UTC. The collection run ID is `c7342874-1113-4d4e-93df-277b6b2a4c0e`.

## Included records

| Location | Contents |
|---|---|
| [events/case-events.xml](events/case-events.xml) | 30 selected native XML event elements |
| [events/case-events.jsonl](events/case-events.jsonl) | The same records in the collection's normalized JSON format |
| [events/selection.json](events/selection.json) | Selection scope, source hashes and individual event identities |
| [configuration](configuration) | Task XML, Run and WMI configuration, endpoint identity, and removal checks |
| [markers](markers) | The seven marker records produced by Task, Registry, WMI and Control |
| [search-results](search-results) | Eight exported Splunk search results |

The source collection contains 2,314 records; the native `MOHAMEDAHMED` scope contains 2,281. The files here are a case selection, not a full EVTX or complete machine-history export. Each included XML Event element retains the original source text; `selection.json` records its SHA-256 and source record identity. Normalized JSON retains source fields while adding the collection run label. That label is not a native Windows event field.

The selection matches task registrations, marker process creation, marker file creation, the named Run value changes, and named WMI subscription operations. These are the records behind searches 01–07. The coverage CSV describes the larger host-scoped collection; its counts are not the number of case events included in this repository.

## Search exports

| Search | Rows | Interpretation |
|---|---:|---|
| 01 — Task registration | 4 | Two case/control tasks and two Defender task registrations |
| 02 — Run key changes | 2 | Run command and RunNotification DWORD |
| 03 — WMI subscription | 6 | Creation and deletion operations for filter, consumer and binding |
| 04 — Process execution | 7 | Marker launches recorded by Sysmon |
| 05 — Marker files | 4 | File creation, not every appended marker |
| 06 — Task Public path | 1 | Narrow action-path match |
| 07 — Security process creation | 7 | Security 4688 records for the marker launches |
| 08 — Coverage | 46 | Provider/event-ID groups in the host-scoped source collection |

`SHA256SUMS` at the repository root covers the published files. These checks establish file integrity, not whether a process or domain is trustworthy.
