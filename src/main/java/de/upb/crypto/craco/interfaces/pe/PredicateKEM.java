package de.upb.crypto.craco.interfaces.pe;

import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism;
import de.upb.crypto.math.serialization.Representation;

/**
 * See PredicateEncryptionScheme. The only difference between
 * the EncryptionScheme and the KeyEncapsulationMechanism (KEM) is
 * that the KEM will not encrypt arbitrary user-defined messages
 * but will instead be able to generate random message-ciphertext
 * pairs (m, c). See KeyEncapsulationMechanism for details.
 *
 * @author Jan
 */
public interface PredicateKEM<T> extends KeyEncapsulationMechanism<T> {
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
     * Shorthand for encaps(generateEncryptionKey(cind));
     */
    default KeyAndCiphertext<T> encaps(CiphertextIndex cind) {
        return encaps(generateEncryptionKey(cind));
    }

    /**
     * Checks whether a holder of a key from kind should be able to
     * decrypt ciphertexts encrypted using cind.
     */
    default boolean checkPredicate(KeyIndex kind, CiphertextIndex cind) {
        return getPredicate().check(kind, cind);
    }
}
