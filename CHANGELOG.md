# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
### Changed
### Fixed
### Docs

## [1.2.2]
### Added
- Two docker-compose files
- Check for presence of .yml or .yaml files in the current directory

### Fixed
- Handle sudden disconnects of CT logs

### Docs
- Added [wiki entry for docker-compose](https://github.com/d-Rickyy-b/certstream-server-go/wiki/Collecting-and-Visualizing-Metrics) 

## [1.2.1]
### Changed
- Updated ci pipeline to use new setup-go and checkout actions
- Use correct package name `github.com/d-Rickyy-b/certstream-server-go`

## [1.2.0] - 2022-12-15
### Added
- Log x-Forwarded-For header for requests
- More logging for certain error situations
- Add operator to ct log cert count metrics

### Changed
- Updated certificate-transparency-go dependency to v1.1.4
- Code improvements, adhering to styleguide
- Rename module to certstream-server-go
- Use log_list.json instead of all_logs_list.json

## [1.1.0] - 2022-10-19
Fix for missing loglist urls.

### Fixed
Fixed the connection issue due to the offline Google loglist urls.

## [1.0.0] - 2022-08-08
Initial release! First stable version of certstream-server-go is published as v1.0.0 

[unreleased]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.2.2...HEAD
[1.2.2]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/d-Rickyy-b/certstream-server-go/tree/v1.0.0
