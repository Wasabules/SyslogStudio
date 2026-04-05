# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Multi-protocol syslog server (UDP, TCP, TLS) with RFC 5424 and RFC 3164 parsing
- Real-time log viewer with virtualized scrolling and auto-scroll
- Advanced filtering: severity, facility, hostname, app name, source IP, full-text search
- Regex search support with toggle
- Date range filtering (from/to datetime)
- TLS / PKI assistant: CA and server certificate generation, mutual TLS, export
- Statistics dashboard: message rates, severity distribution, top sources, buffer usage
- Log export to CSV and plain text
- Configuration persistence (saved to user config directory)
- Light and dark theme with toggle
- Internationalization (English and French)
- Toast notification system for user feedback
- Bounded worker pool (256 goroutines) for message processing
- Structured logging via `log/slog`
- 72 Go unit tests (parser, stats, server, filters)
- TypeScript strict mode
- CI/CD with GitHub Actions (build, test, release)
