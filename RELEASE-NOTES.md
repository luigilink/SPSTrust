# SPSTrust - Release Notes

## [2.0.0] - 2026-07-10

> [!IMPORTANT]
> This is a major release with breaking changes. The package layout moved from
> `scripts/` to `src/`, and the configuration format changed from JSON to a PowerShell
> data file (`.psd1`). Convert your JSON configuration to the equivalent `.psd1` hashtable
> (see the [Configuration](https://github.com/luigilink/SPSTrust/wiki/Configuration) wiki
> page) before upgrading.

### Added

- New reusable `SPSTrust.Common` module (Public/Private layout, manifest-driven version).
- `-LogRetentionDays` parameter with automatic transcript log rotation.
- Example `.psd1` configuration, Pester test suite, PSScriptAnalyzer settings, and a
  Pester CI workflow.
- Wiki sidebar and Release Process page.

### Changed

- **BREAKING**: `scripts/` → `src/`; release archives extract to `SPSTrust.ps1` + `Modules/`.
- **BREAKING**: configuration is now a `.psd1` data file loaded with `Import-PowerShellDataFile`.
- Script version sourced from the module manifest.
- Workflows bumped (`checkout@v7`, `action-gh-release@v3`); README trimmed to defer to the wiki.

### Fixed

- Wiki `Usage` examples (wrong script name and a missing mandatory `-FarmAccount`).

### Removed

- `scripts/` folder, the monolithic `sps.util.psm1` / `util.psm1` modules, and the unused
  `Clear-SPSLog` helper.

A full list of changes in each version can be found in the [change log](CHANGELOG.md).
