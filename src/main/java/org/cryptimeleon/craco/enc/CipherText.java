package org.cryptimeleon.craco.enc;

import org.cryptimeleon.math.serialization.Representable;

/**
 * A ciphertext.
 * <p>
 * Ciphertexts are representable and can be
 * restored from their representation using the appropriate method of
 * the corresponding {@link EncryptionScheme} implementation.
 *
 *
 */
public interface CipherText extends Representable {
}
