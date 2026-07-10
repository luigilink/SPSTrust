# Change log for SPSTrust

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-07-10

### Added

- Read-only **trust matrix** reporting:
  - `Get-SPSTrustStatus` (public) — collects the current cross-farm trust state
    (ROOT, STS, Published, Topology permission, SA permission, Proxy) by calling only
    the read-only `Get-SPS*` functions. Never changes anything; `Content` services are
    reported as N/A for STS/Published/SA-permission/Proxy; getter failures are captured
    as `Error` with a per-row note instead of aborting the audit.
  - `Export-SPSTrustReport` (public) — renders a status object (`-Status`) or a results
    JSON file (`-InputFile`) into a self-contained, offline HTML report with summary
    cards and an interactive (search + click-to-sort) trust matrix.
  - `Backup-SPSJsonFile` (public) — archives the previous results JSON before overwrite.
  - Private HTML report helpers: `ConvertTo-SPSHtmlEncoded`, `Get-SPSReportHtmlHead`,
    `Get-SPSReportCardHtml`, `Get-SPSReportHtmlScript`.
- `SPSTrust.ps1`:
  - `-ReportOnly` switch — read-only audit that skips all four configuration stages and
    only collects state and writes the report.
  - `-HistoryRetentionDays` parameter (default 30) — rotation of archived result
    snapshots in `Results\history\`.
  - A post-run reporting stage (runs after both a normal/clean run and a `-ReportOnly`
    audit): writes `Results\<Application>-<Environment>.json` and
    `Reports\<Application>-<Environment>.html`, archiving the previous snapshot and
    pruning history first.
- Wiki: new `Reports.md` (trust matrix, output layout, regeneration) linked from the
  sidebar; Home and Usage updated for the new parameters and outputs.
- Tests for the collector, the renderer, `Backup-SPSJsonFile`, and the script report
  wiring.

### Changed

- `.gitignore` now excludes the runtime `Logs/`, `Results/` and `Reports/` folders.

## [2.0.0] - 2026-07-10

### Added

- `src/Modules/SPSTrust.Common` module (single source of truth for the version via
  `ModuleVersion`), split into:
  - `Public/` — the 16 trust functions plus `Get-SPSServer` and a generic
    `Clear-SPSLogFolder`.
  - `Private/` — `Invoke-SPSCommand` (CredSSP remoting helper), hidden from callers.
  - `SPSTrust.Common.psm1` loader and `SPSTrust.Common.psd1` manifest.
- `-LogRetentionDays` parameter (default 180, `0` disables pruning); transcript logs are
  now rotated at the end of each run via `Clear-SPSLogFolder`.
- `src/Config/CONTOSO-PROD.example.psd1` example configuration.
- Pester test suite under `tests/` and `PSScriptAnalyzerSettings.psd1`.
- `.github/workflows/pester.yml` running the Pester suite and a PSScriptAnalyzer
  code-quality job on pull requests.
- Wiki: `_Sidebar.md` navigation and `Release-Process.md`.

### Changed

- **BREAKING**: repository layout moved from `scripts/` to `src/`. Release archives now
  extract straight to `SPSTrust.ps1` and `Modules/` (no `scripts/` wrapper).
- **BREAKING**: configuration format changed from JSON to a PowerShell data file
  (`.psd1`). `-ConfigFile` now validates a `*.psd1` path and is loaded with
  `Import-PowerShellDataFile`.
- The script version is now sourced from the `SPSTrust.Common` manifest instead of a
  hard-coded string.
- `release.yml`: bump `actions/checkout@v4` → `@v7` and `softprops/action-gh-release@v2`
  → `@v3`; package the contents of `src/`; add explicit `permissions: contents: write`.
- `wiki.yml`: bump `actions/checkout@v4` → `@v7`.
- README trimmed to defer to the wiki; removed the inaccurate "class-based resources"
  wording.
- Wiki pages (Home, Getting-Started, Configuration, Usage) rewritten for the new layout
  and `.psd1` configuration.

### Fixed

- Wiki `Usage` examples referenced `.\SPSWeather.ps1` instead of `SPSTrust.ps1`, and the
  `-CleanServices` example omitted the mandatory `-FarmAccount`.

### Removed

- `scripts/` folder and the monolithic `sps.util.psm1` / `util.psm1` modules (replaced by
  `SPSTrust.Common`).
- Unused `Clear-SPSLog` helper (superseded by `Clear-SPSLogFolder`).

## [1.0.0] - 2023-11-05

### Added

- Add RELEASE-NOTES.md file
- Add CHANGELOG.md file
- Add CONTRIBUTING.md file
- Add release.yml file
- Add scripts folder with first version of SPSTrust
- README.md
  - Add code_of_conduct.md badge
- Add CODE_OF_CONDUCT.md file
- Add Issue Templates files:
  - 1_bug_report.yml
  - 2_feature_request.yml
  - 3_documentation_request.yml
  - 4_improvement_request.yml
  - config.yml
- Wiki Documentation in repository - Add :
  - wiki/Home.md
  - wiki/Getting-Started.md
  - wiki/Configuration.md
  - wiki/Usage.md
  - .github/workflows/wiki.yml

### Changed

- SPSTrust.ps1:
  - Update parameter description
  - Add [ValidateScript({ Test-Path $_ -and $_ -like '*.json' })] in ConfigFile parameter
  - Add missing comments
  - Add CleanServices :
    - Publish the service application section
    - Permissions on Application Discovery and Load Balancing Service Application
    - Permission to a published service application for a consuming farm
