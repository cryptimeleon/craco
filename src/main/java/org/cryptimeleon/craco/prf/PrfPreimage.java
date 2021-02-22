package org.cryptimeleon.craco.prf;

import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;


/**
 * Input for a {@link PseudorandomFunction}.
 */
public interface PrfPreimage extends Representable, UniqueByteRepresentable {

}
