package de.upb.crypto.craco.common.interfaces;

import de.upb.crypto.math.serialization.Representable;

/**
 * A key that is used for decrypting ciphertexts.
 * <p>
 * DecryptionKeys are representable and can be
 * restored from their representation using the appropriate method of
 * the corresponding {@link EncryptionScheme} implementation.
 */
public interface DecryptionKey extends Representable {
}
