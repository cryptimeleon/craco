package org.cryptimeleon.craco.prf;

import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;


/**
 * Key used to parameterize a {@link PseudorandomFunction}.
 */
public interface PrfKey extends Representable, UniqueByteRepresentable {

}
