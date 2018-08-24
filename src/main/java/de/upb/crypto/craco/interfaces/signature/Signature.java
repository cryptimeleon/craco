package de.upb.crypto.craco.interfaces.signature;

import de.upb.crypto.math.serialization.Representable;

/**
 * A signature.
 * <p>
 * Signature are Representable and can be
 * restored from Representation using the appropriate method of
 * the SignatureScheme interface.
 *
 * @author feidens
 */
public interface Signature extends Representable {
    public static final String RECOVERY_METHOD = "getSignature";
}
