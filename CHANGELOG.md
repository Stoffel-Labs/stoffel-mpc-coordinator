# Changelog

## 0.2.1

### Added

- Added an optional browser-client listener served over server-authenticated TLS, with per-request P-256 signatures, timestamp/nonce replay protection, and WebAuthn-based binding of ephemeral browser keys to registered client identities (`browser_rpc`, `OffChainCoordinatorServer::start_coord_with_browser_tls`).
- Added `run-coord` flags `--browser-addr`, `--browser-port`, `--browser-tls-cert-chain`, `--browser-tls-key`, `--webauthn-rp-id`, `--client-cert-dir`, and `--client-credential-id-dir`.
- Added the `request_shutdown` RPC method and `run-coord --one-off-shutdown-grace-secs`.

### Changed

- One-off coordinators now exit only when the designated party calls `request_shutdown` after the execution reached `ProgramFinished`, then wait a bounded grace period for the remaining parties to acknowledge, instead of shutting down on the round transition itself.

### Fixed

- Fixed clients participating in multiple executions, and prevented a client from logging in again after it has submitted its input.

## 0.2.0 - 2026-08-28

### Added

- Added strict 256-bit execution identifiers for isolating coordinator runs.
- Added persistent and concurrent off-chain executions, including one-off registration and clean shutdown once the execution reached `ProgramFinished` (superseded by explicit `request_shutdown` in 0.2.1).
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
