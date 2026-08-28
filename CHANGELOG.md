# Changelog

## 0.2.0 - 2026-08-28

### Added

- Added strict 256-bit execution identifiers for isolating coordinator runs.
- Added persistent and concurrent off-chain executions, including one-off registration and clean shutdown after `ProgramFinished`.
- Added batched input-mask reservation and masked-input submission APIs.
- Added voting-based round transitions so execution control no longer depends on one designated party.

### Changed

- Centralized package metadata and dependency versions in the workspace manifest.
- Updated the coordinator libraries to the 0.1.1 Stoffel networking, VM types, and MPC protocol crates.
- Reduced repeated client-certificate traffic and bound preprocessing masks to exact client input ranges.
- Documented the split workspace, published packages, and 0.2.0 installation paths.

### Fixed

- Fixed duplicate connections, completed subscriptions, straggling parties, and concurrent execution cleanup from blocking other coordinator work.
- Fixed input-share requests being rejected incorrectly and drained stale messages before execution state is reused.
- Made test crypto-provider initialization idempotent when another dependency has already installed Rustls's process-wide provider.

## 0.1.0 - 2026-06-22

### Added

- Initial release-prep metadata for the `stoffel-mpc-coordinator` crate.
- Coordinator trait and round model for Stoffel MPC protocol execution.
- Off-chain coordinator over secure JSON-RPC with mutual TLS.
- On-chain coordinator integration with the Stoffel coordinator smart contract via Alloy.
- Support for HoneyBadger `RobustShare` and Feldman/Shamir verifiable shares through the `ShareBound` abstraction.
- Test/deployment binaries for contract deployment, local coordinator startup, and identity generation.

### Known limitations

- crates.io publishing is blocked until the pinned Stoffel Solidity SDK binding crates are published or removed from the public dependency graph.
