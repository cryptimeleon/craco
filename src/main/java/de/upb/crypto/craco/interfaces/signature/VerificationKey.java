package de.upb.crypto.craco.interfaces.signature;

import de.upb.crypto.math.serialization.Representable;


/**
 * A key that is used to verify signatures.
 * <p>
 * VerificationKeys are Representable and can be
 * restored from Representation using the appropriate method of
 * the SignatureScheme interface.
 *
 * @author feidens
 */
public interface VerificationKey extends Representable {
    public static final String RECOVERY_METHOD = "getVerificationKey";
}
