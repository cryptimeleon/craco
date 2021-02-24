package org.cryptimeleon.craco.commitment;

import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;

/**
 * A commitment to some value.
 */
public interface Commitment extends Representable, UniqueByteRepresentable {
}
