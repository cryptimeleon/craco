package de.upb.crypto.craco.common.interfaces;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

/**
 * A key that is used to encrypt plaintexts.
 * <p>
 * EncryptionKeys are representable and can be
 * restored from their representation using the appropriate method of
 * the corresponding {@link EncryptionScheme} implementation.
 */
public interface EncryptionKey extends Representable, UniqueByteRepresentable {
    public static final String RECOVERY_METHOD = "getEncryptionKey";

}
