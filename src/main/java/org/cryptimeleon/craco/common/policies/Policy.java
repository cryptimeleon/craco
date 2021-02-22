package org.cryptimeleon.craco.common.policies;

import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;

import java.util.Collection;

/**
 * A {@code Policy} is an object that can be fulfilled by a set of {@link PolicyFact}s.
 */
public interface Policy extends StandaloneRepresentable, CiphertextIndex, KeyIndex, UniqueByteRepresentable {
    boolean isFulfilled(Collection<? extends PolicyFact> facts);
}
