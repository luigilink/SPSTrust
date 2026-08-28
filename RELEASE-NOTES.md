# SPSTrust - Release Notes

## [3.0.0] - 2026-08-28

> [!IMPORTANT]
> This is a major release with a breaking change: support for SharePoint Server 2016 and
> 2019 has been removed. If you still run SharePoint Server 2016 or 2019, stay on the
> previous major release (v2.1.0).

### Removed

- **BREAKING**: dropped support for SharePoint Server 2016 and 2019 (both reached end of
  support on 14 July 2026). The deprecated `Microsoft.SharePoint.PowerShell` PSSnapin path
  (`Add-PSSnapin`) has been removed from the CredSSP remoting base script.

### Changed

- **BREAKING**: the remoting base script now loads the Subscription Edition
  `SharePointServer` module (`Import-Module SharePointServer`, idempotent) as the only
  supported code path.
- Documentation (README, wiki) updated to state compatibility with SharePoint Server
  Subscription Edition only.

### Migration

- Users still running SharePoint Server 2016 or 2019 must stay on the previous major
  release (**v2.1.0**), which retains the PSSnapin code path.

A full list of changes in each version can be found in the [change log](CHANGELOG.md).
