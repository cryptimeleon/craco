package org.cryptimeleon.craco.common.plaintexts;

import org.cryptimeleon.craco.enc.EncryptionScheme;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;

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
