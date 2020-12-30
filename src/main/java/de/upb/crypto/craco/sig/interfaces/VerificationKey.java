package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.math.serialization.Representable;


/**
 * A key that is used to verify signatures.
 * <p>
 * {@code VerificationKeys} are {@code Representable} and can be
 * restored from {@code Representation} using the appropriate method of
 * the {@code SignatureScheme} interface.
 *
 * @author feidens
 */
public interface VerificationKey extends Representable {
    public static final String RECOVERY_METHOD = "getVerificationKey";
}
