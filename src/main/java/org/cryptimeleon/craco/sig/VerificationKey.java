package org.cryptimeleon.craco.sig;

import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;


/**
 * A key that is used to verify signatures.
 * <p>
 * {@code VerificationKeys} are {@link Representable} and can be
 * restored from {@link Representation} using {@link SignatureScheme#restoreVerificationKey(Representation)}.
 *
 *
 */
public interface VerificationKey extends Representable {
}
