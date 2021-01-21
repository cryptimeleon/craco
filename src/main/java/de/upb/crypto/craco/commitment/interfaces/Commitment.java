package de.upb.crypto.craco.commitment.interfaces;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

/**
 * A commitment to some value.
 */
public interface Commitment extends Representable, UniqueByteRepresentable {
}
