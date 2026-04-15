# Changelog

All notable changes to this project are documented in this file.

## v4.0 - 2026-04-15

### Added
- Adaptive scan mode with runtime feedback loop.
- Adaptive decision logging and summary metrics in JSON output.
- Health badge in CLI summary (`GOOD`, `NOISY`, `AGGRESSIVE`).
- Priority policy profiles and custom policy support.
- Extended passive sources: `crt.sh` + `BufferOver`.
- DNS verification hardening (`A`, `AAAA`, `CNAME`) with stability checks.
- Bounded queue + worker model for scalable concurrency.
- CI pipeline with automated tests.

### Changed
- Default behavior strengthened for false-positive reduction.
- TLS handling made secure by default with optional `--insecure`.
- Output schema expanded with richer metadata and scoring insights.

### Quality
- Test coverage expanded progressively; current suite passes in CI/local.
