package de.upb.crypto.craco.interfaces.proxy;

import de.upb.crypto.math.serialization.Representable;

/**
 * A key that is used to transform a ciphertext to another ciphertext,
 * possibly belonging to another scheme and possibly hiding a different
 * plaintext.
 *
 * @author Jan
 */
public interface TransformationKey extends Representable {

}
