package de.upb.crypto.craco.sig;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;


/**
 * A key that is used to verify signatures.
 * <p>
 * {@code VerificationKeys} are {@link Representable} and can be
 * restored from {@link Representation} using {@link SignatureScheme#getVerificationKey(Representation)}.
 *
 *
 */
public interface VerificationKey extends Representable {
}
