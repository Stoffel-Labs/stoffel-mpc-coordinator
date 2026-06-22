# Changelog

## 0.1.0 - 2026-06-22

### Added

- Initial release-prep metadata for the `stoffel-mpc-coordinator` crate.
- Coordinator trait and round model for Stoffel MPC protocol execution.
- Off-chain coordinator over secure JSON-RPC with mutual TLS.
- On-chain coordinator integration with the Stoffel coordinator smart contract via Alloy.
- Support for HoneyBadger `RobustShare` and Feldman/Shamir verifiable shares through the `ShareBound` abstraction.
- Test/deployment binaries for contract deployment, local coordinator startup, and identity generation.

### Known limitations

- crates.io publishing is blocked until git dependencies on Stoffel crates are replaced with registry dependencies or those dependencies are otherwise published in a compatible form.
