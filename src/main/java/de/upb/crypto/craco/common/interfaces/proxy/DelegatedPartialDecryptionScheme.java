package de.upb.crypto.craco.common.interfaces.proxy;

import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionScheme;
import de.upb.crypto.math.serialization.Representation;

/**
 * A delegated partial decryption scheme is an encryption scheme where
 * the owner of a decryption key can generate some "transformation key"
 * that allows any party ("proxy") to transform a ciphertext of the scheme
 * to a ciphertext (of potentially a different scheme) (without learning the
 * plaintext).
 * <p>
 * The usual process of "partially-proxy-decrypting" a ciphertext c of this encryption scheme
 * is:
 * - make sure you have a decryption key dk that could directly decrypt the ciphertext (i.e. decrypt() works)
 * - get transformation key tf and decryption key dk' from generateTransformationKey(dk)
 * - anyone can now, given tf, transform the ciphertext c to a ciphertext c' using transform(c, tf)
 * - c' can be decrypted using getSchemeForTransformedCiphertexts().decrypt(c', dk')
 *
 * @author Jan
 */
public interface DelegatedPartialDecryptionScheme extends EncryptionScheme {
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
    public EncryptionScheme getSchemeForTransformedCiphertexts();

    /**
     * Recreates a transformation key from representation
     */
    public TransformationKey recreateTransformationKey(Representation repr);
}
