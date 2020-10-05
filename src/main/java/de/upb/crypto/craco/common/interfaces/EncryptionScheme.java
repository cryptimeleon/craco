package de.upb.crypto.craco.common.interfaces;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.v2.RepresentationRestorer;

import java.lang.reflect.Type;

/**
 * An EncryptionScheme has the ability to encrypt plaintexts
 * and decrypt the resulting ciphertext (using EncryptionKeys and DecryptionKeys).
 * <p>
 * The functional contract is that decrypt(encrypt(m, pk), sk) = m for pk, sk that
 * "fit" together (depending on the concrete type of encryption scheme).
 * <p>
 * Sub-Interfaces define how you obtain encryption and decryption keys.
 * Cf. AsymmetricEncryptionScheme for a very simple example.
 * <p>
 * EncryptionSchemes are stand-alone representable. So once set up,
 * you can restore the same scheme with the same public parameters
 * using the Representation mechanism (i.e. call the class's constructor
 * with a Representation argument).
 *
 * @author Jan
 */
public interface EncryptionScheme extends StandaloneRepresentable, RepresentationRestorer {

    CipherText encrypt(PlainText plainText, EncryptionKey publicKey);

    PlainText decrypt(CipherText cipherText, DecryptionKey privateKey);

    PlainText getPlainText(Representation repr);

    CipherText getCipherText(Representation repr);

    EncryptionKey getEncryptionKey(Representation repr);

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