package org.cryptimeleon.craco.accumulator;

import org.cryptimeleon.math.serialization.StandaloneRepresentable;

/**
 * Interface for a witness of an accumulator.
 */
public interface AccumulatorWitness extends StandaloneRepresentable {
    /**
     * @return name of witnesses, unique in every protocol
     */
    String getName();
}
