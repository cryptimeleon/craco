package de.upb.crypto.craco.kem.abe.interfaces.proxy;

import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism;
import de.upb.crypto.math.serialization.Representation;

/**
 * See DelegatedPartialDecryptionScheme
 */
public interface DelegatedPartialDecapsulationScheme<T> extends KeyEncapsulationMechanism<T> {
    public static class TransformationAndDecryptionKey {
        public TransformationKey transformationKey;
        public DecryptionKey decryptionKey;
    }

    /**
     * Transforms a ciphertext of this scheme to a ciphertext of
     * another scheme.
     *
     * @param original     the original ciphertext
     * @param transformKey
     * @return a transformed ciphertext for the scheme returned by getSchemeForTransformedCiphertexts()
     */
    public CipherText transform(CipherText original, TransformationKey transformKey);

    /**
     * Takes a decryption key of this encryption scheme and
     * generates a transformation key to use with this scheme,
     * and a decryption key that can be used to decrypt ciphertexts
     * that are the result of transformation with the transformation key.
     *
     * @param original the original decryption key
     * @return a transformation key and a decryption key for the getSchemeForTransformedCiphertexts() scheme
     */
    public TransformationAndDecryptionKey generateTransformationKey(DecryptionKey original);

    /**
     * Returns the scheme that the transformed ciphertexts are meaningful to.
     */
    public KeyEncapsulationMechanism<T> getSchemeForTransformedCiphertexts();

    /**
     * Recreates a transformation key from representation
     */
    public TransformationKey recreateTransformationKey(Representation repr);
}
