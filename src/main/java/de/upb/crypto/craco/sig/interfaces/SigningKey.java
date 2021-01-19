package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

/**
 * A key that is used to generate a signature.
 * <p>
 * {@code SigningKey}s are {@link Representable} and can be restored from their {@link Representation}
 * using {@link SignatureScheme#getSigningKey(Representation)}.
 *
 *
 */
public interface SigningKey extends Representable {
    public static final String RECOVERY_METHOD = "getSigningKey";
}
