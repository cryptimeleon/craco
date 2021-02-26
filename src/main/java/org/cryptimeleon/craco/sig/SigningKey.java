package org.cryptimeleon.craco.sig;

import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

/**
 * A key that is used to generate a signature.
 * <p>
 * {@code SigningKey}s are {@link Representable} and can be restored from their {@link Representation}
 * using {@link SignatureScheme#restoreSigningKey(Representation)}.
 *
 *
 */
public interface SigningKey extends Representable {
}
