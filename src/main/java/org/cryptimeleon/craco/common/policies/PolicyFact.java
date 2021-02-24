package org.cryptimeleon.craco.common.policies;

import org.cryptimeleon.craco.secretsharing.accessstructure.AccessStructure;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;

/**
 * A set of {@code PolicyFact}s can be used to fulfill a {@link Policy}.
 * <p>
 * Also used to represent share receivers for {@link AccessStructure}.
 */
public interface PolicyFact extends StandaloneRepresentable {

}
