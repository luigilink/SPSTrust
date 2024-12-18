# SPSTrust - Release Notes

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

A full list of changes in each version can be found in the [change log](CHANGELOG.md)
