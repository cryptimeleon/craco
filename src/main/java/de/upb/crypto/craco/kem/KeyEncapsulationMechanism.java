package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.UnqualifiedKeyException;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A mechanism that is able to generate random symmetric keys and
 * encrypt/decrypt them to build hybrid encryption schemes.
 * For this purpose, encrypt and decrypt are called encaps and decaps, respectively.
 * <p>
 * The usual use case is:
 * - call encaps() to get a random symmetric key k and an encrypted version c
 * - hand c to the receiver
 * - the receiver calls decaps(c), which yields k
 * - the receiver now has the same random key k as you.
 * <p>
 * <p>
 * Cramer, Ronald, and Victor Shoup. Design and Analysis of Practical Public-Key Encryption Schemes Secure against
 * Adaptive Chosen Ciphertext Attack. SIAM Journal on Computing 33, no. 1 (2003): 167-226.
 * Page 201.
 */
public interface KeyEncapsulationMechanism<T> extends StandaloneRepresentable {
    public static class KeyAndCiphertext<T> {
        public T key;
        public CipherText encapsulatedKey;
    }

    /**
     * Randomly chooses a key k and encrypts it
     * w.r.t. the given pk. The result is (key, encapsulatedKey)
     *
     * @param pk public key used for encrypting k
     */
    public KeyAndCiphertext<T> encaps(EncryptionKey pk);

    /**
     * Takes an encapsulatedKey that was created by encaps()
     * and decrypts it with sk.
     * i.e. 	if (key, encapsulatedKey) <- encaps(pk);
     * then decrypt(encapsulatedKey, sk) = key.
     */
    public T decaps(CipherText encapsulatedKey, DecryptionKey sk) throws UnqualifiedKeyException;

    public CipherText getEncapsulatedKey(Representation repr);

    public EncryptionKey getEncapsulationKey(Representation repr);

    public DecryptionKey getDecapsulationKey(Representation repr);
}
