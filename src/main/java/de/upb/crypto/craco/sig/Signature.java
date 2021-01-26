package de.upb.crypto.craco.sig;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

/**
 * A signature.
 * <p>
 * {@code Signature}s are {@link Representable} and can be
 * restored from their {@link Representation} using {@link SignatureScheme#getSignature(Representation)}.
 *
 * @author feidens
 */
public interface Signature extends Representable {
}
