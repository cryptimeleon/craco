package de.upb.crypto.craco.common.policies;

import de.upb.crypto.craco.common.predicate.CiphertextIndex;
import de.upb.crypto.craco.common.predicate.KeyIndex;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

import java.util.Collection;

/**
 * A {@code Policy} is an object that can be fulfilled by a set of {@link PolicyFact}s.
 */
public interface Policy extends StandaloneRepresentable, CiphertextIndex, KeyIndex, UniqueByteRepresentable {
    boolean isFulfilled(Collection<? extends PolicyFact> facts);
}
