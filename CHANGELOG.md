# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Latest]

## [3.0.1]

### Changed
- math version from 3.0.0 to 3.0.1

## [3.0.0]

### Added
- Added simplified version of Goth SPS from ASIACRYPT'15 `SPSGroth15SignatureScheme` (see [#85](https://github.com/cryptimeleon/craco/issues/85))

### Changed
- Changed uses `Zn#getInteger()` from Math library to `RingElement#asInteger()` to address removal of the former from the Math library
- Moved general methods in interface `StructurePreservingSignatureEQScheme` to new interface `MultiMessageStructurePreservingSignatureScheme` to enable implementations of structure-preserving sigature schemes that are not on equivilance classes

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

[Latest]: https://github.com/cryptimeleon/craco/compare/v3.0.1...HEAD
[3.0.1]: https://github.com/cryptimeleon/craco/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/cryptimeleon/craco/compare/v2.1.0...v3.0.0
[2.1.0]: https://github.com/cryptimeleon/craco/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/cryptimeleon/craco/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/cryptimeleon/craco/releases/tag/v1.0.0
