package de.upb.crypto.craco.common.interfaces;

import de.upb.crypto.math.serialization.Representable;

/**
 * A ciphertext.
 * <p>
 * Ciphertexts are representable and can be
 * restored from their representation using the appropriate method of
 * the corresponding {@link EncryptionScheme} implementation.
 *
 * @author Jan
 */
public interface CipherText extends Representable {
    public static final String RECOVERY_METHOD = "getCipherText";
}
