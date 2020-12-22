package de.upb.crypto.craco.common.interfaces.pe;

import de.upb.crypto.craco.abe.interfaces.AbePredicate;
import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.math.serialization.Representation;

/**
 * A {@code PredicateEncryptionScheme} is an advanced form of {@code EncryptionScheme}
 * where ciphertexts can be read by a whole well-defined set of
 * key holders. (One special case is attribute-based encryption).
 * <p>
 * The general idea is that a concrete scheme employs a predicate P (cf. {@link #getPredicate()})
 * and a master secret key that is generally computed during setup (for which there is no common interface and which
 * depends on the scheme).
 * Consider the following process:
 * <pre>
 * sk = generateDecryptionKey(masterSecret, keyIndex);
 * pk = generateEncryptionKey(ciphertextIndex);
 * c = encrypt(m, pk);
 * mPrime = decrypt(c, sk);
 * </pre>
 * Correctness says that if {@code P.check(keyIndex, ciphertextIndex) == true}, then {@code mPrime.equals(m)}.
 * Security says that if {@code P.check(keyIndex, ciphertextIndex) == true}, then the holder of sk cannot decrypt c.
 * <p>
 * Hence at encryption time, a user can choose {@code ciphertextIndex} to determine which group of
 * key holders should be able to decrypt the encrypted message.
 * <p>
 * One special case of predicate encryption is attribute-based encryption.
 * See {@link AbePredicate} for more details on how the predicate works there.
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
     * decrypt ciphertexts where {@code getPredicate().check(kind, cind) == true}.
     *
     * @param msk the master secret obtained during setup
     * @param kind the key index specifying which ciphertexts are decryptable
     * @return the decryption key
     */
    DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind);

    /**
     * Generates an encryption key such that ciphertexts created using
     * that key are decryptable using keys where {@code getPredicate().check(kind, cind) == true}.
     *
     * @param cind the ciphertext index specifying who should be able to decrypt the ciphertext
     * @return the encryption key
     */
    EncryptionKey generateEncryptionKey(CiphertextIndex cind);

    /**
     * The predicate of this {@code PredicateEncryptionScheme}.
     *
     * @see Predicate
     */
    Predicate getPredicate();

    /**
     * Shorthand for {@code encrypt(plainText, generateEncryptionKey(cind))}.
     * 
     * @see #encrypt(PlainText, EncryptionKey) 
     *
     * @param plainText the plaintext to encrypt
     * @param cind ciphertext index defining who should be able to read the ciphertext
     * @return the ciphertext
     */
    default CipherText encrypt(PlainText plainText, CiphertextIndex cind) {
        return encrypt(plainText, generateEncryptionKey(cind));
    }

    /**
     * Checks whether a holder of a key from {@code kind} should be able to
     * decrypt ciphertexts encrypted using {@code cind}.
     */
    default boolean checkPredicate(KeyIndex kind, CiphertextIndex cind) {
        return getPredicate().check(kind, cind);
    }
}
