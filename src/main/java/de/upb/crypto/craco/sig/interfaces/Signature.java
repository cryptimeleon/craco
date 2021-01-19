package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

/**
 * A signature.
 * <p>
 * {@code Signature}s are {@link Representable} and can be
 * restored from their {@link Representation} using {@link SignatureScheme#getSignature(Representation)}.
 *
 *
 */
public interface Signature extends Representable {
    public static final String RECOVERY_METHOD = "getSignature";
}
