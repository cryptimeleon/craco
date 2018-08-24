package de.upb.crypto.craco.interfaces;

import de.upb.crypto.math.serialization.Representable;

/**
 * A ciphertext.
 * <p>
 * Ciphertexts are Representable and can be
 * restored from Representation using the appropriate method of
 * the EncryptionScheme interface.
 *
 * @author Jan
 */
public interface CipherText extends Representable {
    public static final String RECOVERY_METHOD = "getCipherText";
}
