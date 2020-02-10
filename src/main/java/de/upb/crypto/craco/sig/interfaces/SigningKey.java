package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.math.serialization.Representable;

/**
 * A key that is used to generate a signature
 * <p>
 * SigningKeys are Representable and can be restored from Representation
 * using the appropriate method of the SignatureScheme interface.
 *
 * @author feidens
 */
public interface SigningKey extends Representable {
    public static final String RECOVERY_METHOD = "getSigningKey";
}
