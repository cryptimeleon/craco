package de.upb.crypto.craco.common.interfaces;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

/**
 * A plaintext.
 * <p>
 * PlainTexts are representable and can be
 * restored from their representation using the appropriate method of
 * the corresponding {@link EncryptionScheme} implementation.
 *
 * @author Jan
 */
public interface PlainText extends Representable, UniqueByteRepresentable {
    public static final String RECOVERY_METHOD = "getPlainText";
}
