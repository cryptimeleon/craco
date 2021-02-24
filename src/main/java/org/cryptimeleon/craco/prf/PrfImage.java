package org.cryptimeleon.craco.prf;

import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;

/**
 * Output of a {@link PseudorandomFunction}.
 */
public interface PrfImage extends Representable, UniqueByteRepresentable {

}
