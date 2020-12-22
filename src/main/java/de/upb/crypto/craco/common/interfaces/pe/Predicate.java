package de.upb.crypto.craco.common.interfaces.pe;

/**
 * Defines who gets to decrypt which ciphertexts.
 *
 * @see PredicateEncryptionScheme#getPredicate()
 *
 * @author Jan
 */
public interface Predicate {
    /**
     * Checks whether a holder of a key from {@code kind} should be able to
     * decrypt ciphertexts encrypted using {@code cind}.
     *
     * @return true if the decryption is possible, else false
     */
    boolean check(KeyIndex kind, CiphertextIndex cind);
}
