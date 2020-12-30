package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.math.serialization.Representable;

/**
 * A key that is used to generate a signature.
 * <p>
 * {@code SigningKey}s are {@code Representable} and can be restored from {@code Representation}
 * using the appropriate method of the {@code SignatureScheme} interface.
 *
 * @author feidens
 */
public interface SigningKey extends Representable {
    public static final String RECOVERY_METHOD = "getSigningKey";
}
