package de.upb.crypto.craco.prf;

import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;


/**
 * Input for a {@link PseudorandomFunction}.
 */
public interface PrfPreimage extends Representable, UniqueByteRepresentable {

}
