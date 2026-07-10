# SPSTrust - Release Notes

## [2.1.0] - 2026-07-10

This release adds a read-only **trust matrix** report, produced both at the end of a
normal run and in a new dedicated audit mode. It is fully backward compatible with 2.0.0.

### Added

- **`-ReportOnly`** — read-only audit mode: skips all configuration stages and only
  collects the current trust state and writes the report (changes nothing).
- **Trust matrix report** — every run now writes a JSON snapshot
  (`Results\<Application>-<Environment>.json`) and a self-contained, offline HTML report
  (`Reports\<Application>-<Environment>.html`) showing, per publishing-farm /
  consuming-farm / service, the state of each trust dimension (ROOT, STS, Published,
  Topology permission, SA permission, Proxy) as Present / Absent / N/A / Error.
- New public functions in `SPSTrust.Common`: `Get-SPSTrustStatus` (read-only collector),
  `Export-SPSTrustReport` (HTML renderer, also usable standalone via `-InputFile`) and
  `Backup-SPSJsonFile`.
- **`-HistoryRetentionDays`** (default 30) — rotation of archived result snapshots in
  `Results\history\`.
- Wiki: new **Reports & Audit** page.

### Changed

- `.gitignore` excludes the runtime `Logs/`, `Results/` and `Reports/` folders.

### Compatibility

- No breaking changes. Existing `-ConfigFile` / `-FarmAccount` / `-CleanServices` usage is
  unchanged; the reporting stage is additive and read-only.

A full list of changes in each version can be found in the [change log](CHANGELOG.md).
