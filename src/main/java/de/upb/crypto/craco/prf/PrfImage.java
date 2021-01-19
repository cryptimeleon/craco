package de.upb.crypto.craco.prf;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

/**
 * Output of a {@link PseudorandomFunction}.
 */
public interface PrfImage extends Representable, UniqueByteRepresentable {

}
