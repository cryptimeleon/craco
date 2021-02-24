![Build Status](https://github.com/upbcuk/upb.crypto.craco/workflows/Java%20CI/badge.svg)
## Craco

Craco (CRyptogrAphic COnstructions) is a Java library providing implementations of various cryptographic primitives and low-level constructions. This includes primitives such as commitment schemes, signature schemes, and much more.

The goal of Craco is to provide common cryptographic schemes for usage in more high-level protocols as well as to offer facilities for improving the process of implementing more low-level schemes such as signature and encryption schemes.

## Security Disclaimer
**WARNING: This library is meant to be used for prototyping and as a research tool *only*. It has not been sufficiently vetted for use in security-critical production environments. All implementations are to be considered experimental.**


## Features

Craco implements interfaces and tests for basic cryptographic primitives such as commitment schemes, encryption schemes, and more.

We also implement a number of such schemes.

### Implemented Schemes
The constructions provided are:

* **Accumulators**:
    * Nguyen's dynamic accumulator [Ngu05]
* **Commitment schemes**:
    * Pedersen's commitment scheme [Ped92]
* **Digital signature schemes**:
    * Pointcheval & Sanders' short randomizable signature scheme [PS16]
    * An extension of Boneh, Boyen and Shacham's signature scheme from [Eid15]
    * Pointcheval & Sanders' modified short randomizable signature scheme (with and without ROM) [PS18]
    * Hanser and Slamanig's structure-preserving signature scheme on equivalence classes [HS14]
* **Encryption schemes**:
    * ElGamal
    * Streaming AES Encryption using CBC and GCM modes of operation
* **Key encapsulation mechanisms (KEM)**: 
    * ElGamal
* **Secret sharing schemes**:
    * Shamir's secret sharing scheme [Sha79] and its tree extension

## Quickstart

### Installation With Maven
To add the newest Craco version as a dependency, add this to your project's POM:

```xml
<dependency>
    <groupId>org.cryptimeleon</groupId>
    <artifactId>craco</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Installation With Gradle

Craco is published via Maven Central.
Therefore, you need to add `mavenCentral()` to the `repositories` section of your project's `build.gradle` file.
Then, add `implementation group: 'org.cryptimeleon', name: 'craco', version: '1.0.0'` to the `dependencies` section of your `build.gradle` file.

For example:

```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation group: 'org.cryptimeleon', name: 'craco', version: '1.0.0'
}
```

### Tutorials

Craco is very much connected with our [Math library](https://github.com/cryptimeleon/math).
Therefore, we recommend you go through our [short Math tutorial](https://cryptimeleon.github.io/getting-started/5-minute-tutorial.html) to get started.

We also provide walkthroughs where we show you how to implement a pairing-based signature scheme [here](https://cryptimeleon.github.io/getting-started/pairing-tutorial.html) as well as a simple cryptographic protocol [here](https://cryptimeleon.github.io/getting-started/protocols-tutorial.html).

## Documentation

Our official documentation page can be found [here](https://cryptimeleon.github.io/). 
Keep in mind that the documentation is written for all the Cryptimeleon libraries.

## Versioning
Craco adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Changelog
The changelog can be found [here](CHANGELOG.md).

## Dependencies

See the `dependencies` section of this project's [Gradle build configuration](build.gradle) for a detailed list of dependencies.

## How to Contribute
Our documentation page includes [information for contributors](https://cryptimeleon.github.io/contributors/contributing.html).
This includes information on the build process.

## Notes

The library was implemented at Paderborn University in the research group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/).

## Licence
Apache License 2.0, see LICENCE file.
