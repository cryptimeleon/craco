package de.upb.crypto.craco.secretsharing.policy;

import de.upb.crypto.craco.secretsharing.accessstructure.AccessStructure;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * A set of {@code PolicyFact}s can be used to fulfill a {@link Policy}.
 * <p>
 * Also used to represent share receivers for {@link AccessStructure}.
 */
public interface PolicyFact extends StandaloneRepresentable {

}
