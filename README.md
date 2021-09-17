![Build Status](https://github.com/cryptimeleon/craco/workflows/Development%20Java%20CI/badge.svg)
![Build Status](https://github.com/cryptimeleon/craco/workflows/Main%20Java%20CI/badge.svg)
![Build Status](https://github.com/cryptimeleon/craco/workflows/Scheduled%20Main%20Java%20CI/badge.svg)
## Craco

Craco (CRyptogrAphic COnstructions) is a Java library providing implementations of various cryptographic primitives and low-level constructions. This includes primitives such as commitment schemes, signature schemes, facilities for implementing multi-party protocols, and much more.

The goal of Craco is to provide common cryptographic schemes for usage in more high-level protocols as well as to offer facilities for improving the process of implementing more low-level schemes such as signature and encryption schemes.

## Security Disclaimer
**WARNING: This library is meant to be used for prototyping and as a research tool *only*. It has not been sufficiently vetted for use in security-critical production environments. All implementations are to be considered experimental.**

## Table Of Contents

* [Features Overview](#features)
* [Quickstart Guide](#quickstart)
    * [Maven Installation](#installation-with-maven)
    * [Gradle Installation](#installation-with-gradle)
    * [Tutorials](#tutorials)
* [Miscellaneous Information](#miscellaneous-information)
* [Authors](#authors)
* [References](#references)

## Features

Craco implements interfaces and test classes for basic cryptographic primitives such as commitment schemes, encryption schemes, and more.
It also includes implementations of several schemes as well as facilities for implementing two-party protocols.

### Implemented Schemes
The constructions we implement are:

* **Accumulators**:
    * Nguyen's dynamic accumulator [Ngu05]
* **Commitment schemes**:
    * Pedersen's commitment scheme [Ped92]
* **Digital signature schemes**:
    * Pointcheval & Sanders' short randomizable signature scheme [PS16]
    * An extension of Boneh, Boyen and Shacham's signature scheme from [Eid15]
    * Pointcheval & Sanders' modified short randomizable signature scheme (with and without ROM) [PS18]
    * Fuchsbauer, Hanser and Slamanig's structure-preserving signature scheme on equivalence classes [FHS19]
* **Encryption schemes**:
    * ElGamal
    * Streaming AES Encryption using CBC and GCM modes of operation
* **Key encapsulation mechanisms (KEM)**: 
    * ElGamal
* **Secret sharing schemes**:
    * Shamir's secret sharing scheme [Sha79] and its tree extension
    
### Protocols

Craco also includes interfaces and basic classes useful for implementing cryptographic two-party protocols.
Parts of this are facilities for easy implementation of Sigma protocols.

Furthermore, it includes:

* A Fiat-Shamir transformation implementation
* A Schnorr protocol implementation
* An implementation of Damgård's technique used to improve Sigma protocols

## Quickstart

### Installation With Maven
To add the newest Craco version as a dependency, add this to your project's POM:

```xml
<dependency>
    <groupId>org.cryptimeleon</groupId>
    <artifactId>craco</artifactId>
    <version>3.0.0</version>
</dependency>
```

### Installation With Gradle

Craco is published via Maven Central.
Therefore, you need to add `mavenCentral()` to the `repositories` section of your project's `build.gradle` file.
Then, add `implementation group: 'org.cryptimeleon', name: 'craco', version: '3.0.0'` to the `dependencies` section of your `build.gradle` file.

For example:

```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation group: 'org.cryptimeleon', name: 'craco', version: '3.0.0'
}
```

### Tutorials

Craco is very much connected with our [Math library](https://github.com/cryptimeleon/math).
Therefore, we recommend you go through our [short Math tutorial](https://cryptimeleon.github.io/getting-started/5-minute-tutorial.html) to get started.

We also provide walkthroughs where we show you how to implement a pairing-based signature scheme [here](https://cryptimeleon.github.io/getting-started/pairing-tutorial.html) as well as a simple cryptographic protocol [here](https://cryptimeleon.github.io/getting-started/protocols-tutorial.html).
The latter uses Craco's protocol capabilities.

## Miscellaneous Information

- Official Documentation can be found [here](https://cryptimeleon.github.io/).
    - The *For Contributors* area includes information on how to contribute.
- Craco adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
- The changelog can be found [here](CHANGELOG.md).
- Craco is licensed under Apache License 2.0, see [LICENSE file](LICENSE).

## Authors
The library was implemented at Paderborn University in the research group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/).

## References

[FHS19] Georg Fuchsbauer and Christian Hanser and Daniel Slamanig. "Structure-Preserving Signatures on Equivalence Classes and Constant-Size Anonymous Credentials". In: Journal of Cryptology, 2019. Vol. 32, pp. 498 - 546.

[Ngu05] Lan Nguyen. “Accumulators from Bilinear Pairings and Applications”. In: Topics in Cryptology – CT-RSA 2005. Ed. by Alfred Menezes. Vol. 3376. Lecture Notes in Computer Science. Springer, Heidelberg, February 2005, pp. 275–292.

[Ped92] Torben P. Pedersen. “Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing”. In: Advances in Cryptology – CRYPTO’91. Ed. by Joan Feigenbaum. Vol. 576. Lecture Notes in Computer Science. Springer, Heidelberg, August 1992, pp. 129–140.

[PS16] David Pointcheval and Olivier Sanders. “Short Randomizable Signatures”. In: Topics in Cryptology – CT-RSA 2016. Ed. by Kazue Sako. Vol. 9610. Lecture Notes in Computer Science. Springer, Heidelberg, February 2016, pp. 111–126.

[PS18] David Pointcheval and Olivier Sanders. "Reassessing Security of Randomizable Signatures". In: Topic in Cryptology - CT-RSA 2018. Ed. by Nigel P. Smart. Springer International Publishing, 2018, pp 319-338.

[Sha79] Adi Shamir. “How to Share a Secret”. In: Communications of the Association for Computing Machinery 22.11 (November 1979), pp. 612–613.
