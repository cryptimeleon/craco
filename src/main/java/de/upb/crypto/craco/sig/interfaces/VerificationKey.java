package de.upb.crypto.craco.sig.interfaces;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;


/**
 * A key that is used to verify signatures.
 * <p>
 * {@code VerificationKeys} are {@link Representable} and can be
 * restored from {@link Representation} using {@link SignatureScheme#getVerificationKey(Representation)}.
 *
 * @author feidens
 */
public interface VerificationKey extends Representable {
    public static final String RECOVERY_METHOD = "getVerificationKey";
}
