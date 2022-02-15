package org.cryptimeleon.craco.commitment.trapdoorcommitment;

import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;

/**
 * Equivocation key used to generate a trapdoor opening to a message
 */
public interface EquivocationKey extends Representable, UniqueByteRepresentable {
}
