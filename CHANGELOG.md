# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Pointcheval & Sanders' signature schemes from "Reassessing Security of Randomizable Signatures", 2018
- Fuchsbauer, Hanser and Slamanig's signature scheme from "Structure-Preserving Signatures on Equivalence Classes and Constant-Size Anonymous Credentials", 2014

### Changed
- Reordered many packages to improve organization
- Updated Gradle to version 6.4

### Fixed

### Removed
- ABE and ABE-KEM schemes as they have been moved to the [Predenc library](https://github.com/upbcuk/upb.crypto.predenc)
- Log4j dependency
- Json-simple dependency
- Key derivation functions
- `ByteArrayQueue` and `Triple` classes (not used)
- `interaction` package (not used)
- `PrimeFieldPolynomial` and `SecureRandomGenerator` classes (replaced by other functionality)
- `WatersHash` class (moved to Predenc project) and `LagrangeUtil` class (moved to Math project)
- Author tags

## [1.1.0] - 2019-01-11

### Added
- Initial release

[Unreleased]: https://github.com/upbcuk/upb.crypto.craco/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/upbcuk/upb.crypto.craco/releases/tag/v1.1.0