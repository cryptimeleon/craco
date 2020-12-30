package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.math.serialization.Representable;

/**
 * A signature.
 * <p>
 * Signature are {@code Representable} and can be
 * restored from {@code Representation} using the appropriate method of
 * the {@link SignatureScheme} interface.
 *
 * @author feidens
 */
public interface Signature extends Representable {
    public static final String RECOVERY_METHOD = "getSignature";
}
