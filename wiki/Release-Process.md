# Release Process

This page documents how to ship a new version of SPSTrust. The process is centered on a
single source of truth — the `ModuleVersion` field of `SPSTrust.Common.psd1` — and a `v*`
git tag that triggers the GitHub release workflow.

## Versioning policy

SPSTrust follows [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html).

| Bump | When |
|---|---|
| MAJOR (X.0.0) | Breaking change in the package layout, the configuration schema, or a public module function signature. |
| MINOR (X.Y.0) | New backward-compatible feature (new parameter, new public function, new capability). |
| PATCH (X.Y.Z) | Bug fix or documentation-only change. |

## Release checklist

### 1. Bump the version

Edit **one** value in `src/Modules/SPSTrust.Common/SPSTrust.Common.psd1`:

```powershell
ModuleVersion = '2.0.0'   # was '1.0.0'
```

This single change propagates automatically to the script banner
(`$SPSTrustVersion` is read from `(Get-Module SPSTrust.Common).Version`).

### 2. Update `CHANGELOG.md`

Add a dated section for the version being released, following
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

### 3. Replace `RELEASE-NOTES.md`

`RELEASE-NOTES.md` is used **verbatim** as the body of the GitHub Release. It must contain
**only** the section of the version being released (no stacked history).

### 4. Validate locally

```powershell
Import-Module .\src\Modules\SPSTrust.Common\SPSTrust.Common.psd1 -Force
(Get-Module SPSTrust.Common).Version    # should match the bumped version
Invoke-Pester -Path .\tests
Invoke-ScriptAnalyzer -Path .\src -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

### 5. Commit on a release branch

```bash
git checkout -b Release/2.0.0
git add -A
git commit -m "release: v2.0.0"
git push -u origin Release/2.0.0
```

Test the branch ZIP on a real farm first, then open a Pull Request, review, and merge to `main`.

### 6. Tag from `main`

```bash
git checkout main
git pull
git tag v2.0.0
git push origin v2.0.0
```

The `.github/workflows/release.yml` workflow runs automatically. It:

1. Packages the **contents** of `src/` into `SPSTrust-v2.0.0.zip` (the archive extracts
   straight to `SPSTrust.ps1` and `Modules\`, with no `src/` wrapper).
2. Publishes a GitHub Release using `RELEASE-NOTES.md` as the body.
3. Attaches the ZIP and `LICENSE` to the release.

### 7. Verify

- **Releases**: <https://github.com/luigilink/SPSTrust/releases> — the new release is listed with the expected body and ZIP.
- **Actions**: <https://github.com/luigilink/SPSTrust/actions> — `release.yml` and `pester.yml` ran green.
- **Wiki**: <https://github.com/luigilink/SPSTrust/wiki> — `wiki.yml` synced any `wiki/` changes pushed in the same release.

## Undoing a release

If you tagged too early:

```bash
git tag -d v2.0.0
git push origin --delete v2.0.0
```

Then delete the auto-created Release on GitHub, fix what needs fixing, commit, and re-tag from the new HEAD.

> ⚠️ **Don't move a published tag** that has been live for more than a few minutes. Prefer publishing a `vX.Y.(Z+1)` patch release instead of rewriting `vX.Y.Z`.

## See also

- [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
- [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html)
- [Getting Started](Getting-Started)
- [Usage](Usage)
