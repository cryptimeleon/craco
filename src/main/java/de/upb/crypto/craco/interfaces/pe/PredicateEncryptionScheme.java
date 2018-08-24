package de.upb.crypto.craco.interfaces.pe;

import de.upb.crypto.craco.interfaces.*;
import de.upb.crypto.math.serialization.Representation;

/**
 * A PredicateEncryptionScheme is an advanced form of EncryptionScheme
 * where ciphertexts can be read by a whole well-defined set of
 * key holders. (One special case is attribute-based encryption).
 * <p>
 * The general idea is that a concrete scheme employs a predicate P (cf. getPrediate())
 * and a master secret key that is generally computed during setup (for which there is no common interface and which
 * depends on the scheme).
 * Consider the following process:
 * sk = generateDecryptionKey(masterSecret, keyIndex);
 * pk = generateEncryptionKey(ciphertextIndex);
 * c = encrypt(m, pk);
 * m' = decrypt(c, sk);
 * <p>
 * Correctness says that if P(keyIndex, ciphertextIndex) = 1, then m' = m.
 * Security says that if P(keyIndex, ciphertextIndex) = 0, then the holder of sk cannot decrypt c.
 * <p>
 * Hence at encryption time, a user can choose ciphertextIndex to determine which group of
 * key holders should be able to decrypt the encrypted message.
 * <p>
 * One special case of predicate encryption is attribute-based encryption.
 * See the class AbePredicate for more details.
 *
 * @author Jan
 */
public interface PredicateEncryptionScheme extends EncryptionScheme {
    /**
     * Recreates a master secret key from its representation.
     */
    MasterSecret getMasterSecret(Representation repr);

    /**
     * Generates a decryption key that will be able to
     * decrypt ciphertexts where getPredicate().check(kind, cind) = 1.
     *
     * @param msk  the master secret obtained during setup.
     * @param kind the key index specifying which ciphertexts are readable.
     * @return a key used for decrypt().
     */
    DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind);

    /**
     * Generates an encryption key such that ciphertexts created using
     * that key are decryptable using keys where getPredicate().check(kind, cind) = 1.
     *
     * @param cind the ciphertext index specifying who should be able to read the ciphertext.
     * @return a key used for encrypt().
     */
    EncryptionKey generateEncryptionKey(CiphertextIndex cind);

    /**
     * The predicate of this PredicateEncryptionScheme (see that interface's Javadoc).
     */
    Predicate getPredicate();

    /**
     * Shorthand for encrypt(plainText, generateEncryptionKey(cind));
     *
     * @param plainText plaintext to encrypt.
     * @param cind      ciphertext index defining who should be able to read the ciphertext.
     * @return the ciphertext.
     */
    default CipherText encrypt(PlainText plainText, CiphertextIndex cind) {
        return encrypt(plainText, generateEncryptionKey(cind));
    }

    /**
     * Checks whether a holder of a key from kind should be able to
     * decrypt ciphertexts encrypted using cind.
     */
    default boolean checkPredicate(KeyIndex kind, CiphertextIndex cind) {
        return getPredicate().check(kind, cind);
    }
}
