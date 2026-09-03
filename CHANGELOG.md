# Changelog

All notable changes to the OJS Codec Server will be documented in this file.

## [Unreleased]

## [0.5.0] - 2026-09-02

### Added
- Standalone CI, dependency automation, security scanning, release-readiness checks, and community contribution files.

### Fixed
- Build images and CLI version metadata now match the Go module and current release.
- The runtime container now uses a non-root user and includes a health check.

## [0.4.0] - 2026-04-20

### Changed

- Compatibility update for OJS v0.4.0 job envelope format
- Dependency updates

## [0.1.0] — 2026-03-07

### Added

- Initial release of the OJS Codec Server
- `POST /codec/encode` — encrypt payloads with AES-256-GCM
- `POST /codec/decode` — decrypt payloads using key ID lookup
- `GET /health` — server health check
- Multi-key support with key rotation via environment variables
- CORS middleware for dashboard integration
- Dockerfile for containerized deployment
- 17 unit tests covering crypto, handlers, and CORS
