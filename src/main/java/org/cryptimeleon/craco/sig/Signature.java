package org.cryptimeleon.craco.sig;

import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

/**
 * A signature.
 * <p>
 * {@code Signature}s are {@link Representable} and can be
 * restored from their {@link Representation} using {@link SignatureScheme#getSignature(Representation)}.
 *
 *
 */
public interface Signature extends Representable {
}
