![Build Status](https://github.com/upbcuk/upb.crypto.craco/workflows/Java%20CI/badge.svg)
## Craco

Craco (CRyptogrAphic COnstructions) is a Java library providing implementations of various cryptographic primitives and low-level constructions. This includes primitives such as commitment schemes, signature schemes, and much more.

The goal of Craco is to provide common cryptographic schemes for usage in more high-level protocols as well as to offer facilities for improving the process of implementing more low-level schemes such as signature and encryption schemes.

Craco also includes mathematical building blocks as provided by the [Math library](https://github.com/upbcuk/upb.crypto.craco).


## Security Disclaimer
**WARNING: This library is meant to be used for prototyping and as a research tool *only*. It has not been sufficiently vetted for use in security-critical production environments. All implementations are to be considered experimental.**

## Table of Contents
Add this last

## How to Install
- java 8 library obtainable via maven central (once its actually up there)

### Maven
- How maven dependency configuration should look like

### Gradle
- How to add it to build.gradle

## Versioning
Craco adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Changelog
The changelog can be found [here](https://github.com/upbcuk/upb.crypto.craco/blob/master/CHANGELOG.md).

## Features

### Implemented Schemes
The constructions provided are:

* **Accumulators**:
    * Nguyen's dynamic accumulator [Ngu05]
* **Commitment schemes**:
    * Pedersen's commitment scheme [Ped92]
* **Digital signature schemes**:
    * Pointcheval's & Sanders' short randomizable signature scheme [PS16]
    * An extension of Boneh's, Boyen's and Shacham's signature scheme from [Eid15]
    * Pointcheval's & Sanders' modified short randomizable signature scheme (with and without ROM) [PS18]
    * Fuchsbauer's, Hanser's and Slamanig's structure-preserving signature scheme on equivalence classes [FHS14]
* **Encryption schemes**:
    * ElGamal
    * Streaming AES Encryption using CBC and GCM modes of operation
* **Key encapsulation mechanisms (KEM)**: 
    * ElGamal
* **Secret sharing schemes**:
    * Shamir's secret sharing scheme [Sha79] and its tree extension
    
### ABE, ABE-KEM and Group Signatures
Craco does not provide such high-level constructions.

You can find our attribute-based encryption schemes and key encapsulation mechanisms [here](https://github.com/upbcuk/upb.crypto.predenc).

Group signatures can be found [here](https://github.com/upbcuk/upb.crypto.groupsig).
    
## Documentation

We have a documentation page for our combined libraries [here](https://upbcuk.github.io/).

## Example Code

- Include example here or link to one in the docs?
- We do not have a tutorial specific to Craco in the docs.

## Dependencies

Craco relies on the following dependencies:

- [upb.crypto.math](https://github.com/upbcuk/upb.crypto.math) version 2.0.0 for mathematical foundations
- [Reflections](https://github.com/ronmamo/reflections) version 0.9.10 for testing (maybe update the version?)
- [JUnit](https://junit.org/junit5/) versions 4.12 and 5 for testing

## How to Contribute
Our documentation page includes [information for contributors](https://upbcuk.github.io/contributors/contributing.html).
This includes information on the build process.

## References

[Ngu05] Lan Nguyen. “Accumulators from Bilinear Pairings and Applications”. In: Topics
in Cryptology – CT-RSA 2005. Ed. by Alfred Menezes. Vol. 3376. Lecture Notes in
Computer Science. Springer, Heidelberg, February 2005, pp. 275–292.

[Ped92] Torben P. Pedersen. “Non-Interactive and Information-Theoretic Secure Verifiable
        Secret Sharing”. In: Advances in Cryptology – CRYPTO’91. Ed. by Joan Feigenbaum.
        Vol. 576. Lecture Notes in Computer Science. Springer, Heidelberg, August
        1992, pp. 129–140.

[PS16] David Pointcheval and Olivier Sanders. “Short Randomizable Signatures”. In: Topics
in Cryptology – CT-RSA 2016. Ed. by Kazue Sako. Vol. 9610. Lecture Notes in
Computer Science. Springer, Heidelberg, February 2016, pp. 111–126.

[Sha79] Adi Shamir. “How to Share a Secret”. In: Communications of the Association for
Computing Machinery 22.11 (November 1979), pp. 612–613.

## Notes

The library was implemented at Paderborn University in the research group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/).

## Licence
Apache License 2.0, see LICENCE file.
