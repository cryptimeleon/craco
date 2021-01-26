package de.upb.crypto.craco.accumulators.interfaces;


import de.upb.crypto.math.serialization.StandaloneRepresentable;

import java.util.Set;


/**
 * Interface for an accumulator which works over a static set of {@link AccumulatorIdentity}, reflecting the
 * theoretical properties of 'Accumulators' in combination with
 * the de.upb.crypto.craco.interfaces in accumulators.de.upb.crypto.craco.interfaces.
 * <p>
 * It contains the following methods of the theoretical definition:
 * AccCreate
 * WitCreate
 * Vrfy
 */
public interface StaticAccumulator<IdentityType extends AccumulatorIdentity> extends StandaloneRepresentable {

    /**
     * Accumulates set of {@link AccumulatorIdentity} by calculating and returning the {@link AccumulatorValue}
     *
     * @param setOfIdentities Set of {@link AccumulatorIdentity} to be accumulated
     * @return {@link AccumulatorValue} for accumulated set of {@link AccumulatorIdentity}
     */
    AccumulatorValue create(Set<IdentityType> setOfIdentities);

    /**
     * Create a {@link AccumulatorWitness} for single {@link AccumulatorIdentity} which is part of the set of
     * accumulated
     * {@link AccumulatorIdentity}
     *
     * @param setOfIdentities Set of accumulated {@link AccumulatorIdentity}
     * @param singleIdentity  Single {@link AccumulatorIdentity} that shall receive a {@link AccumulatorWitness}
     * @return {@link AccumulatorWitness} for single {@link AccumulatorIdentity}
     */
    AccumulatorWitness createWitness(Set<IdentityType> setOfIdentities,
                                     IdentityType singleIdentity);

    /**
     * Verifies whether a single {@link AccumulatorIdentity} accumulated in an accumulator by checking the
     * {@link AccumulatorWitness} for single {@link AccumulatorIdentity} against the {@link AccumulatorValue}
     *
     * @param accumulatorValue         {@link AccumulatorValue}
     * @param singleIdentity           Single {@link AccumulatorIdentity}
     * @param witnessForSingleIdentity {@link AccumulatorWitness} for single {@link AccumulatorIdentity}
     * @return Iff  a single {@link AccumulatorIdentity} has a correct {@link AccumulatorWitness} for the
     * {@link AccumulatorValue} returns true; else false.
     */
    boolean verify(AccumulatorValue accumulatorValue,
                   IdentityType singleIdentity, AccumulatorWitness witnessForSingleIdentity);
}
