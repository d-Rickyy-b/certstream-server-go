# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Ability to store and resume processing of certs from where it left off after a restart - see sample config "recovery" (#49)
- New CLI switch for creating an index file from a CT log (#49)
- Check for retired CT logs and prevent them from being watched / stop watching them (#77)
- Accept websocket connections from all origins
- Option to disable the default logs provided by Google - see sample config "disable_default_logs"
### Changed
### Removed
- Non-functional Dodo log from sample config (#78)
### Fixed
- Properly remove stopped ct log workers (#74)
- Added missing fields certificatePolicies and ctlPoisonByte (#85)
- Prevent race condition caused by simultaneous rw access to logmetrics
### Docs

## [v1.8.2] - 2025-11-22
### Fixed
- Added missing fields certificatePolicies and ctlPoisonByte (#85)

## [v1.8.1] - 2025-05-04
### Fixed
- No longer reject URLs with trailing slashes defined in the `additional_logs` config (#62)
- When using `drop_old_logs` in the config, the server won't remove logs defined in `additional_logs` anymore (#64)

## [v1.8.0] - 2025-05-03
### Security
- Close several CVEs in x/crypto and x/net dependencies (#59)

### Added
- New CLI tool for fetching certificates from a CT log (#47)
- Ability to add custom CT logs to the config (#56)
- Remove old CT logs as soon as they are removed from the Google CT Loglist (#60)
- New configuration for buffer sizes (#58)

### Fixed
- Properly handle IPv6 addresses in config (#61)

## [1.7.1] - 2025-05-03
### Fixed
- Properly handle IPv6 addresses in config (#61)

## [1.7.0] - 2024-08-20
### Added
- Support for websocket compression - disabled by default (#40)
- Support for non-browsers by implementing server initiated heartbeats (#39)
- Start new ct-watchers as new ct logs become available (#42)
- More logging to document currently watched logs (03d878e)
 
### Changed
- Changed log output to be better grepable (5c055cc)
- Update ct log update interval to once per hour instead of once per 6 hours as previously (9b6e77d)

### Fixed
- Fixed a possible race condition when accessing metrics

## [1.6.0] - 2024-03-05
### Added
- New metric for skipped certs per client (#34)

## [1.5.2] - 2024-02-17
### Fixed
- Fixed an issue with ip whitelists for the websocket server (#33)

## [1.5.1] - 2024-01-18
### Fixed
- Fixed a rare issue where it was possible for the all_domains json property (or data property in case of the domains-only endpoint) to be null 

## [1.5.0] - 2023-12-21
### Added
- New `-version` switch to print version and exit afterwards
- Print version on every run of the tool
- Count and log number of skipped certificates per client

### Changed
- Update to chi/v5
- Update ct-watcher timeout from 5 to 30 seconds

### Fixed
- Prevent invalid subscription types to be used
- Kill connection after broadcasthandler was stopped

## [1.4.0] - 2023-11-29
### Added
- Config option to use X-Forwarded-For or X-Real-IP header as client IP
- Config option to whitelist client IPs for both websocket and metrics endpoints
- Config option to enable system metrics (cpu, memory, etc.)

## [1.3.2] - 2023-11-28
### Fixed
- Memory leak related to clients disconnecting from the websocket not being handled properly

## [1.3.1] - 2023-09-18
### Changed
- Updated config.sample.yaml to run both certstream and prometheus metrics on same socket

### Docs
- Fixed wrong docker command in readme

## [1.3.0] - 2023-04-11
### Added
- Calculate and display Sha256 sum of certificate

### Changed
- Update dependencies
- Better logging for CT log errors

### Fixed
- End execution after all workers stopped
- Implement timeout for the http client
- Keep ct watcher from crashing upon a connection reset from server

## [1.2.2] - 2023-01-10
### Added
- Two docker-compose files
- Check for presence of .yml or .yaml files in the current directory

### Fixed
- Handle sudden disconnects of CT logs

### Docs
- Added [wiki entry for docker-compose](https://github.com/d-Rickyy-b/certstream-server-go/wiki/Collecting-and-Visualizing-Metrics) 

## [1.2.1] - 2022-12-16
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

[unreleased]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.8.2...HEAD
[1.8.2]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.7.1...v1.8.0
[1.7.1]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.5.2...v1.6.0
[1.5.2]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.3.2...v1.4.0
[1.3.2]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/d-Rickyy-b/certstream-server-go/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/d-Rickyy-b/certstream-server-go/tree/v1.0.0
