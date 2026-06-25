# Changelog

All notable changes to CRACKbaby are recorded here. Versions follow
[semantic versioning](https://semver.org/).

## Unreleased

- Per-phase crack counts are now additive across runs: an interrupt→resume sums both
  segments and a clean re-run no longer zeros a completed phase.
- README intro tidied; cross-platform support (Windows, macOS, Linux) called out explicitly.

## v1.0.2

- Fixed keyspace calculation for custom-charset (`-1/-2/-3/-4`) phases and large wordlists,
  so ETAs and time-gating are accurate.
- Cleaned up raw hashcat passthrough during a run.
- Reworded the "campaign already exists" hint.
- Aligned the keyspace pre-flight line with the phase header and hashcat output.

## v1.0.1

- Colorized, organised terminal output — panels, tables, and status badges; auto-plain when
  piped or with `--no-color`.

## v1.0.0

- Initial public release: `prep → init → run → report` NTLM recovery pipeline with
  prioritised phases, per-phase resume, benchmark-calibrated ETAs, LM fast-path, org-targeted
  wordlists, and a text/JSON pentest report.
