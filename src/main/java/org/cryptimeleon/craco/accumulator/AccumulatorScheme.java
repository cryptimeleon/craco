package org.cryptimeleon.craco.accumulator;


import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.RepresentationRestorer;

import java.lang.reflect.Type;
import java.util.Collection;
import java.util.HashSet;

/**
 * An accumulator scheme, i.e. essentially a hash function that takes a set of values and creates a short digest for this set.
 * One can compute witnesses for elements included in the digest, which enables fast verification of set membership.
 * @param <AccumulatedType> the type of values that can be accumulated with this scheme.
 */
public interface AccumulatorScheme<AccumulatedType extends Representable> extends StandaloneRepresentable, RepresentationRestorer {

    /**
     * Creates the accumulator for the given set of values (essentially a collision-resistant hash of setOfValues)
     */
    AccumulatorDigest createDigest(Collection<? extends AccumulatedType> setOfValues);

    /**
     * Creates a short witness that can be used to verify set membership in an accumulator.
     * @param setOfAccumulatedValues the set of values accumulated (including valueToComputeWitnessFor)
     * @param valueToComputeWitnessFor the one value you want to prove is in there
     * @return a short witness to be used in {@link AccumulatorScheme#verify(AccumulatorDigest, Representable, AccumulatorWitness)}
     */
    AccumulatorWitness createWitness(AccumulatorDigest digest, Collection<? extends AccumulatedType> setOfAccumulatedValues, AccumulatedType valueToComputeWitnessFor);

    /**
     * Verifies that the given singleValue is indeed part of the accumulated set.
     */
    boolean verify(AccumulatorDigest accumulatorDigest, AccumulatedType singleValue, AccumulatorWitness witnessForSingleValue);

    /**
     * Given an accumulator for setOfValues, computes an accumulator for setOfValues ∪ {additionalValue}.
     */
    default AccumulatorDigest insert(AccumulatorDigest digest, Collection<? extends AccumulatedType> setOfValues, AccumulatedType additionalValue) {
        HashSet<AccumulatedType> newValues = new HashSet<>(setOfValues);
        newValues.add(additionalValue);
        return createDigest(newValues);
    }

    /**
     * Given an accumulator for setOfValues, computes an accumulator for setOfValues \ {additionalValue}.
     */
    default AccumulatorDigest delete(AccumulatorDigest digest, Collection<? extends AccumulatedType> setOfValues, AccumulatedType valueToDelete) {
        HashSet<AccumulatedType> newValues = new HashSet<>(setOfValues);
        newValues.remove(valueToDelete);
        return createDigest(newValues);
    }

    /**
     * Updates a set membership witness w.r.t. accumulator changes.
     * Equivalent to recomputing a witness using {@link AccumulatorScheme#createWitness(AccumulatorDigest, Collection, Representable)}, but this method may be more efficient.
     *
     * @param oldDigest the "old" digest
     * @param newDigest the "new" digest
     * @param oldAccumulatedSet the set accumulated in oldDigest
     * @param newAccumulatedSet the set accumulated in newDigest
     * @param valueToComputeWitnessFor the value (present in oldDigest and in newDigest) for which a witness shall be computed.
     * @param oldWitnessToBeUpdated a witness for valueToComputeWitnessFor being part of oldDigest
     * @return a witness for valueToComputeWitnessFor being part of newDigest (same as {@code createWitness(newAccumulatedSet, valueToComputeWitnessFor)})
     */
    default AccumulatorWitness updateWitness(AccumulatorDigest oldDigest, AccumulatorDigest newDigest,
                                             Collection<? extends AccumulatedType> oldAccumulatedSet, Collection<? extends AccumulatedType> newAccumulatedSet,
                                             AccumulatedType valueToComputeWitnessFor, AccumulatorWitness oldWitnessToBeUpdated) {
        return createWitness(newDigest, newAccumulatedSet, valueToComputeWitnessFor);
    }

    /**
     * @return Maximum number of {@link AccumulatedType}s that can be simultaneously accumulated in the Accumulator or null if unbounded
     */
    Integer getMaxNumAccumulatedValues();

    AccumulatorWitness restoreWitness(Representation repr);
    AccumulatorDigest restoreDigest(Representation repr);
    AccumulatedType restoreAccumulatedValue(Representation repr);

    @Override
    default Object recreateFromRepresentation(Type type, Representation repr) throws IllegalArgumentException {
        if (type instanceof Class && AccumulatorWitness.class.isAssignableFrom((Class) type))
            return restoreWitness(repr);
        if (type instanceof Class && AccumulatorDigest.class.isAssignableFrom((Class) type))
            return restoreDigest(repr);

        throw new IllegalArgumentException("Group cannot restore type "+type.getTypeName()+" from representation");
    }
}
