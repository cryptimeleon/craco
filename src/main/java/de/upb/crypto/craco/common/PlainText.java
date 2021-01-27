package de.upb.crypto.craco.common;

import de.upb.crypto.craco.enc.EncryptionScheme;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

/**
 * A plaintext.
 * <p>
 * PlainTexts are representable and can be
 * restored from their representation using the appropriate method of
 * the corresponding {@link EncryptionScheme} implementation.
 *
 *
 */
public interface PlainText extends Representable, UniqueByteRepresentable {
}
