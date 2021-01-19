package de.upb.crypto.craco.commitment.interfaces;

import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;

/**
 * Value used to open a commitment.
 */
public interface OpenValue extends Representable, UniqueByteRepresentable {
}
