package de.upb.crypto.craco.interfaces;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

/**
 * A plaintext.
 * <p>
 * PlainTexts are Representable and can be
 * restored from Representation using the appropriate method of
 * the EncryptionScheme interface.
 *
 * @author Jan
 */
public interface PlainText extends Representable, UniqueByteRepresentable {
    public static final String RECOVERY_METHOD = "getPlainText";

}
