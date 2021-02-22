package org.cryptimeleon.craco.accumulator;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;

import java.util.Set;

/**
 * Interface for an accumulator that allows to dynamically insert/delete {@link AccumulatorIdentity} to/from the
 * accumulator and to
 * dynamically update the corresponding {@link AccumulatorWitness}es. It is reflecting the theoretical properties of
 * 'Accumulators' in combination with the org.cryptimeleon.craco.interfaces in accumulators.org.cryptimeleon.craco.interfaces.
 * <p>
 * It contains the following methods of the theoretical definition:
 * AccInsert
 * AccDelete
 * WitUpdate
 */
public interface DynamicAccumulator<IdentityType extends AccumulatorIdentity> extends StaticAccumulator<IdentityType> {

    /**
     * Inserts a single {@link AccumulatorIdentity} into the {@link DynamicAccumulator} and updates the
     * {@link AccumulatorValue}
     *
     * @param accumulatorValue {@link AccumulatorValue}
     * @param setOfIdentities  Set containing all {@link AccumulatorIdentity}
     * @param singleIdentity   {@link AccumulatorIdentity} to be inserted
     * @return Updated {@link AccumulatorValue} after inserting a {@link AccumulatorIdentity}
     */
    AccumulatorValue insert(AccumulatorValue accumulatorValue, Set<IdentityType> setOfIdentities,
                            IdentityType singleIdentity);

    /**
     * Deletes a single {@link AccumulatorIdentity} from the {@link DynamicAccumulator} and updates the
     * {@link AccumulatorValue}
     *
     * @param accumulatorValue {@link AccumulatorValue}
     * @param setOfIdentities  Set containing all {@link AccumulatorIdentity}
     * @param singleIdentity   {@link AccumulatorIdentity} to be deleted
     * @return Updated {@link AccumulatorValue} after deleting a {@link AccumulatorIdentity}
     */
    AccumulatorValue delete(AccumulatorValue accumulatorValue, Set<IdentityType> setOfIdentities,
                            IdentityType singleIdentity);

    /**
     * Updates the {@link AccumulatorWitness} for a single {@link AccumulatorIdentity} for a changed accumulated set of
     * {@link AccumulatorIdentity}
     *
     * @param oldAccumulatorValue         Old {@link AccumulatorValue}
     * @param currentAccumulatorValue     current {@link AccumulatorValue}
     * @param oldAccumulatedSet           Set containing all {@link AccumulatorIdentity} accumulated in the old
     *                                    {@link DynamicAccumulator} which needs to be updated
     * @param currentAccumulatedSet       Set containing all {@link AccumulatorIdentity} accumulated in the current
     *                                    {@link DynamicAccumulator}
     * @param singleIdentity              {@link AccumulatorIdentity} in old and current Set whose
     *                                    {@link AccumulatorWitness}
     *                                    needs to be updated
     *                                    {@link DynamicAccumulator}s to be updated
     * @param oldWitnessForSingleIdentity {@link AccumulatorWitness} oldWitnessForSingleIdentity with value
     *                                    singleIdentity in
     *                                    old  and current {@link DynamicAccumulator}s to be updated
     * @return Updated {@link AccumulatorValue} for the current accumulated set
     * ({@link MessageBlock})
     */
    AccumulatorWitness update(AccumulatorValue oldAccumulatorValue, AccumulatorValue currentAccumulatorValue,
                              Set<IdentityType> oldAccumulatedSet, Set<IdentityType> currentAccumulatedSet,
                              IdentityType singleIdentity, AccumulatorWitness oldWitnessForSingleIdentity);

}
