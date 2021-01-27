package de.upb.crypto.craco.enc;

import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.RepresentationRestorer;

import java.lang.reflect.Type;

/**
 * An {@code EncryptionScheme} has the ability to encrypt plaintexts
 * and decrypt the resulting ciphertext (using {@link EncryptionKey}s and {@link DecryptionKey}s).
 * <p>
 * The functional contract is that {@code decrypt(encrypt(m, pk), sk).equals(m)} for pk, sk that
 * "fit" together (depending on the concrete type of encryption scheme).
 * <p>
 * Sub-Interfaces define how you obtain encryption and decryption keys.
 * Cf. {@link AsymmetricEncryptionScheme} for a very simple example.
 * <p>
 * {@code EncryptionScheme}s are stand-alone representable. So once set up,
 * you can restore the same scheme with the same public parameters
 * using the {@code Representation} mechanism (i.e. call the class's constructor
 * with a {@code Representation} argument).
 *
 *
 */
public interface EncryptionScheme extends StandaloneRepresentable, RepresentationRestorer {

    /**
     * Encrypts the given plain text using the given encryption key.
     * @param plainText the plaintext to encrypt
     * @param publicKey the key to use for encryption
     * @return the resulting ciphertext
     */
    CipherText encrypt(PlainText plainText, EncryptionKey publicKey);

    /**
     * Decrypts the given cipher text using the given decryption key.
     * @param cipherText the ciphertext to decrypt
     * @param privateKey the key to use for decryption
     * @return the resulting plaintext
     */
    PlainText decrypt(CipherText cipherText, DecryptionKey privateKey);

    /**
     * Restores the plaintext corresponding to the given representation.
     * @param repr the representation to restore the plaintext from
     * @return the plaintext corresponding to the given representation
     */
    PlainText getPlainText(Representation repr);

    /**
     * Restores the ciphertext corresponding to the given representation.
     * @param repr the representation to restore the ciphertext from
     * @return the ciphertext corresponding to the given representation
     */
    CipherText getCipherText(Representation repr);

    /**
     * Restores the encryption key corresponding to the given representation.
     * @param repr the representation to restore the encryption key from
     * @return the encryption corresponding to the given representation
     */
    EncryptionKey getEncryptionKey(Representation repr);

    /**
     * Restores the decryption key corresponding to the given representation.
     * @param repr the representation to restore the decryption key from
     * @return the decryption key corresponding to the given representation
     */
    DecryptionKey getDecryptionKey(Representation repr);

    default CipherText encrypt(Representation plainText, Representation publicKey) {
        return encrypt(getPlainText(plainText), getEncryptionKey(publicKey));
    }

    default PlainText decrypt(Representation cipherText, Representation privateKey) {
        return decrypt(getCipherText(cipherText), getDecryptionKey(privateKey));
    }

    default Object recreateFromRepresentation(Type type, Representation repr) {
        if (type instanceof Class) {
            if (EncryptionKey.class.isAssignableFrom((Class) type)) {
                return this.getEncryptionKey(repr);
            } else if (DecryptionKey.class.isAssignableFrom((Class) type)) {
                return this.getDecryptionKey(repr);
            } else if (CipherText.class.isAssignableFrom((Class) type)) {
                return this.getCipherText(repr);
            } else if (PlainText.class.isAssignableFrom((Class) type)) {
                return this.getPlainText(repr);
            }
        }
        throw new IllegalArgumentException("Cannot recreate object of type: " + type.getTypeName());
    }
}