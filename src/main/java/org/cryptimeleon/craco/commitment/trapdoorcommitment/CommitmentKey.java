package org.cryptimeleon.craco.commitment.trapdoorcommitment;

import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;

/**
 * Commitment key used to commit to messages
 */
public interface CommitmentKey extends Representable, UniqueByteRepresentable {
}
