# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0]

### Added
- `AdHocSchnorrProof` for easy construction of typical Schnorr proofs
- `SigmaProtocol.debugProof(...)` for debugging failing proofs

## [2.0.0] - 2021-06-23

### Added

- Helper methods for `MultiMessageSignatureScheme` and `StructurePreservingSignatureEQScheme` to make signing and verifying multiple plaintexts less verbose
- Added notion of a `ChallengeSpace` (change breaks old `SigmaProtocol` API)
- Proofs of partial knowledge
- `SPSEQSignature` now implements `UniqueByteRepresentable`
- `LongAesPseudoRandomFunction` which uses a longer key to obtain a larger expansion factor
- `HashThenPrfToZn` that generates pseudorandom `Zn` elements using `LongAesPseudoRandomFunction`

### Fixed

- Streaming GCM encryption now correctly uses no padding

### Removed
- PRF classes have been moved to Math

## [1.0.0] - 2021-03-01

Initial release

[Unreleased]: https://github.com/cryptimeleon/craco/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/cryptimeleon/craco/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/cryptimeleon/craco/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/cryptimeleon/craco/releases/tag/v1.0.0
