[![Build Status](https://travis-ci.com/upbcuk/upb.crypto.craco.svg?branch=master)](https://travis-ci.com/upbcuk/upb.crypto.craco)
## upb.crypto.craco
**WARNING: this library is meant to be used for prototyping and as a research tool *only*. It has not been sufficiently vetted to use in production.**

upb.crypto.craco is a library providing cryptographic construction mainly focused on attribute-based schemes.
The library is build upon the math library [upb.crypto.math](https://github.com/upbcuk/upb.crypto.math).

The constructions provided are:

* **Accumulators**:
    * Nguyen's dynamic accumulator [Ngu05]
* **Commitment schemes**:
    * Pedersen's commitment scheme [Ped92]
* **Digital signature schemes**:
    * Pointcheval's & Sanders' short randomizable signature scheme [PS16]
* **Encryption schemes**:
    * ElGamal
    * Attribute-based:
        * Waters' ciphertext-policy attribute-based encryption scheme [Wat11]
        * Goyal et al.'s key-policy attribute-based encryption scheme [GPSW06]
    * Identity-based:
        * Fuzzy identity-based encryption [SW05]
        * Identity based encryption from the Weil pairing [BF01]
* **Key derivation functions (KDF)**:
    * Implementation based on the Leftover-Hash-Lemma
* **Key encapsulation mechanisms (KEM)**: We implemented several KEMs based on the encryption schemes implemented in this library. CRACO provides KEMs for [Wat11], [GPSW06], [SW05] and ElGamal. 
* **Secret sharing schemes**:
    * Shamir's secret sharing scheme [Sha79] and its tree extension

## Example Code

As a starting point, we give code examples for common tasks using this library.

#### Attribute-Based Encryption

The following example code illustrates the usage of [Wat11] ABE scheme. 
It also applies to any other ABE scheme.

```java
/*
 * Generate algorithm parameters:
 * 80 = security level, 5 = the maximum number of attributes in a key, 
 * 5 = maximum number of leaf-node attributes in a policy,
 * usage of Water's hash function = false,
 * debug mode = false
 */
ABECPWat11Setup setup = new ABECPWat11Setup();
ABECPWat11PublicParameters pp = setup.doKeyGen(80, 5, 5, false, false);

// set up the encryption scheme using pp
PredicateEncryptionScheme enc = new ABECPWat11(setup.getPublicParameters());

// get master secret key for the decryption key generation
MasterSecret masterSecret = setup.getMasterSecret();

/* Key generation */

/* Generate a policy for the encryption key (CipherTextIndex)
 * 
 * ((A,B)'1 ,(B, C, D)'2)'2 := (A + B) * (CD + DE + CE)
 */
ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
ThresholdPolicy rightNode = new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));
CiphertextIndex ciphertextIndex = new ThresholdPolicy(2, leftNode, rightNode);

// Generate encryption key using the policy
EncryptionKey encryptionKey = predicateEncryptionScheme.generateEncryptionKey(ciphertextIndex);

// Generate a KeyIndex for the decryption key, here: {A, B, C, D}
KeyIndex keyIndex = new SetOfAttributes(new StringAttribute("A"),  new StringAttribute("C"), new StringAttribute("D"));

// Generate decryption key using master secret key and key index
DecryptionKey decryptionKey = predicateEncryptionScheme.generateDecryptionKey(masterSecret, keyIndex);


/* Encrypting an random element */

// Sample random group element
GroupElement randomElement = publicParameters.getGroupGT().getUniformlyRandomElement();
PlainText plainText = new GroupElementPlainText(randomElement);

// Encrypt it
CipherText cipherText = predicateEncryptionScheme.encrypt(plainText, encryptionKey);

// Decrypt it
PlainText decryptedPlainText = predicateEncryptionScheme.decrypt(cipherText, decryptionKey);

```

The example above is a ciphertext-policy ABE scheme. That is, we encrypt a ciphertext under a policy and equip the decryption key with a set of attributes.
If you want to use a key-policy ABE scheme like [GPSW06] this would be done the other way around, i.e. we equip the ciphertext with a set of attributes and the decryption key with a policy.
To be precise the decryption key's `KeyIndex` then is a policy and the `CiphertextIndex` a set of attributes.

## References

[BF01] Dan Boneh and Matt Franklin. "Identity-Based Encryption from the Weil Pairing". In: Advances in Cryptology — CRYPTO 2001. CRYPTO 2001. Ed. by Joe Kilian. Vol. 2139. Lecture Notes in Computer Science.  Springer, Berlin, Heidelberg, August 2001, pp. 213-229.

[GPSW06] Vipul Goyal, Omkant Pandey, Amit Sahai, and Brent Waters. "Attribute-based encryption for fine-grained access control of encrypted data". In: ACM Conference on Computer and Communications Security. ACM, 2006, pages 89–98.

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

[Wat11] Brent Waters. Ciphertext-policy attribute-based encryption: An
expressive, efficient, and provably secure realization. In Public Key
Cryptography. Springer, 2011, pp. 53–70.

## Notes

The library was implemented at Paderborn University in the research group ["Codes und Cryptography"](https://cs.uni-paderborn.de/en/cuk/).

## Licence
Apache License 2.0, see LICENCE file.
