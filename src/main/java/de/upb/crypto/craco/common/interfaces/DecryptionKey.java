package de.upb.crypto.craco.common.interfaces;

import de.upb.crypto.math.serialization.Representable;

/**
 * A key that is used for decrypting ciphertexts.
 * <p>
 * DecryptionKeys are Representable and can be
 * restored from Representation using the appropriate method of
 * the EncryptionScheme interface.
 */
public interface DecryptionKey extends Representable {
    public static final String RECOVERY_METHOD = "getDecryptionKey";
}
