package de.upb.crypto.craco.prf;

import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;


/**
 * Key used to parameterize a {@link PseudorandomFunction}.
 */
public interface PrfKey extends Representable, UniqueByteRepresentable {

}
