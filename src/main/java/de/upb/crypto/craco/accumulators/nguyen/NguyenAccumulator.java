package de.upb.crypto.craco.accumulators.nguyen;

import de.upb.crypto.craco.accumulators.interfaces.AccumulatorIdentity;
import de.upb.crypto.craco.accumulators.interfaces.AccumulatorValue;
import de.upb.crypto.craco.accumulators.interfaces.AccumulatorWitness;
import de.upb.crypto.craco.accumulators.interfaces.DynamicAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.pairings.generic.BilinearMap;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.polynomial.PolynomialRing;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Implementation of the NguyenAccumulator which is a {@link DynamicAccumulator}
 */
public class NguyenAccumulator implements DynamicAccumulator<NguyenAccumulatorIdentity> {

    @Represented
    public NguyenAccumulatorPublicParameters pp;

    @Represented
    private NguyenAccumulatorValue accumulatorValue;

    @Represented(restorer = "[foo]")
    private Set<NguyenAccumulatorIdentity> identitySet;

    public NguyenAccumulator(NguyenAccumulatorPublicParameters pp) {
        this.pp = pp;
    }

    public NguyenAccumulator(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    /**
     * Calculates the {@link NguyenAccumulatorValue} for a set ({@link NguyenAccumulatorIdentity}) and thereby
     * accumulates it.
     * Furthermore it sets the member variables {@link #accumulatorValue} and {@link #identitySet}
     *
     * @param setOfIdentities Set of {@link AccumulatorIdentity} to be accumulated
     * @return {@link NguyenAccumulatorValue} for a set ({@link NguyenAccumulatorIdentity})
     */
    @Override
    public NguyenAccumulatorValue create(Set<NguyenAccumulatorIdentity> setOfIdentities) {

        if (setOfIdentities.size() > pp.getUpperBoundForAccumulatableIdentities().intValue()) {
            throw new IllegalArgumentException("Too many identities for this accumulator.");
        }
        if (setOfIdentities.isEmpty()) {
            this.setAccumulatorValue(null);
            this.setIdentitySet(Collections.emptySet());
            throw new IllegalArgumentException("The given set is empty.");
        }
        // set member variables
        this.setIdentitySet(setOfIdentities);
        this.setAccumulatorValue(new NguyenAccumulatorValue(createValue(setOfIdentities)));
        return this.accumulatorValue;
    }

    /**
     * Calculates the {@link NguyenAccumulatorValue} for a set ({@link NguyenAccumulatorIdentity}).
     * <p>
     * This method is used for calculating the {@link NguyenAccumulatorValue} or creation of a {@link NguyenWitness}.
     *
     * @param setOfIdentities {@link NguyenAccumulatorIdentity}
     * @return {@link NguyenAccumulatorValue} for a set ({@link NguyenAccumulatorIdentity})
     */
    private GroupElement createValue(Set<NguyenAccumulatorIdentity> setOfIdentities) {

        isValidSetSize(setOfIdentities);

        // create Polynomial
        PolynomialRing polynomialRing = new PolynomialRing(this.pp.getUniverse().get(0).getZp());

        PolynomialRing.Polynomial polynomial = setOfIdentities.stream()
                .map(identity -> createPoly(identity, polynomialRing))
                .reduce(polynomialRing
                        .getOneElement(), PolynomialRing.Polynomial::mul);

        // get coefficients
        RingElement[] coefficients = polynomial.getCoefficients();

        // calculate product
        GroupElement product = pp.getG().getStructure().getNeutralElement();
        for (int i = 0; i < coefficients.length; i++) {
            product = product.op(pp.getT()[i].pow((Zp.ZpElement) coefficients[i]));
        }
        return product.compute();
    }

    private PolynomialRing.Polynomial createPoly(NguyenAccumulatorIdentity identity, PolynomialRing polynomialRing) {
        return polynomialRing.new Polynomial((identity).getIdentity(), pp.getUniverse().get(0).getZp().getOneElement());
    }

    /**
     * Creates a {@link NguyenWitness} for a {@link NguyenAccumulatorIdentity} which is accumulated in the set of
     * {@link NguyenAccumulatorIdentity}.
     *
     * @param setOfIdentities Set of accumulated {@link NguyenAccumulatorIdentity}
     * @param singleIdentity  Single {@link NguyenAccumulatorIdentity} that shall receive a {@link AccumulatorWitness}
     * @return {@link NguyenWitness} for a {@link NguyenAccumulatorIdentity} in the accumulated in the set
     * ({@link NguyenAccumulatorIdentity})
     */
    @Override
    public NguyenWitness createWitness(Set<NguyenAccumulatorIdentity> setOfIdentities, NguyenAccumulatorIdentity
            singleIdentity) {

        Set<NguyenAccumulatorIdentity> set = new HashSet<>(setOfIdentities);
        set.remove(singleIdentity);
        if (set.isEmpty()) {
            return new NguyenWitness(this.pp.getG());
        } else {
            return new NguyenWitness(createValue(set));
        }
    }

    /**
     * Verifies that a {@link NguyenAccumulatorIdentity} is accumulated in a {@link NguyenAccumulator} using a
     * {@link NguyenWitness} and the {@link NguyenAccumulatorValue}.
     * <p>
     * Checks if $e(w_i, \tilde{g}^{x_i} \cdot \tilde{g}^s) = e(V,\tilde{g})$. If the equation holds, \vrfy outputs
     * true, otherwise false.
     *
     * @param accumulatorValue         {@link NguyenAccumulatorValue}
     * @param singleIdentity           Single {@link NguyenAccumulatorIdentity}
     * @param witnessForSingleIdentity {@link NguyenWitness} for single {@link NguyenAccumulatorIdentity}
     * @return boolean whether verify was successful (true) or not (false)
     */
    @Override
    public boolean verify(AccumulatorValue accumulatorValue, NguyenAccumulatorIdentity singleIdentity,
                          AccumulatorWitness
                                  witnessForSingleIdentity) {
        BilinearMap map = this.pp.getBilinearMap();

        if (!(accumulatorValue instanceof NguyenAccumulatorValue)) {
            throw new IllegalArgumentException("AccumulatorValue is not a NguyenAccumulatorValue!");
        }
        if (!(witnessForSingleIdentity instanceof NguyenWitness)) {
            throw new IllegalArgumentException("Witness is not a NguyenWitness!");
        }

        // calculation split into smaller steps
        NguyenWitness w_i = (NguyenWitness) witnessForSingleIdentity;
        GroupElement g_pow_X_i = this.pp.getG_Tilde().pow(singleIdentity.getIdentity());
        GroupElement g_Tilde_prod = g_pow_X_i.op(this.pp.getG_Tilde_Power_S());

        NguyenAccumulatorValue value = ((NguyenAccumulatorValue) accumulatorValue);

        GroupElement lhs = map.apply(w_i.getValue(), g_Tilde_prod);
        GroupElement rhs = map.apply(value.getValue(), this.pp.getG_Tilde());

        return lhs.equals(rhs);
    }


    /**
     * Inserts a {@link NguyenAccumulatorIdentity} into the accumulated set of {@link NguyenAccumulatorIdentity},
     * updates the {@link NguyenAccumulatorValue}. It returns null if the {@link NguyenAccumulatorIdentity} is
     * already contained in the accumulated set.
     * <p>
     * Since the {@link NguyenAccumulator} does not need the {@link AccumulatorValue} for inserting, the
     * call is delegated to {@link #insert(Set, NguyenAccumulatorIdentity)} without the {@link AccumulatorValue}.
     *
     * @param accumulatorValue {@link NguyenAccumulatorValue}
     * @param setOfIdentities  Set containing all {@link NguyenAccumulatorIdentity}
     * @param singleIdentity   {@link NguyenAccumulatorIdentity} to be deleted
     * @return updated {@link NguyenAccumulatorValue} after insertion of {@link NguyenAccumulatorIdentity}
     */
    @Override
    public AccumulatorValue insert(AccumulatorValue accumulatorValue, Set<NguyenAccumulatorIdentity> setOfIdentities,
                                   NguyenAccumulatorIdentity singleIdentity) {
        return insert(setOfIdentities, singleIdentity);
    }

    /**
     * Inserts a {@link NguyenAccumulatorIdentity} into the accumulated set of {@link NguyenAccumulatorIdentity},
     * updates the {@link NguyenAccumulatorValue}. It returns null if the {@link NguyenAccumulatorIdentity} is
     * already contained in the accumulated set.
     *
     * @param setOfIdentities Set containing all {@link NguyenAccumulatorIdentity}
     * @param singleIdentity  {@link NguyenAccumulatorIdentity} to be deleted
     * @return updated {@link NguyenAccumulatorValue} after insertion of {@link NguyenAccumulatorIdentity}
     */
    public AccumulatorValue insert(Set<NguyenAccumulatorIdentity> setOfIdentities,
                                   NguyenAccumulatorIdentity singleIdentity) {
        isValidSetSize(setOfIdentities);

        // check for negative of s
        Zp.ZpElement identity = singleIdentity.getIdentity();
        identity = identity.neg();
        if (this.pp.getG().pow(identity) == this.pp.getT()[1]) {
            throw new IllegalArgumentException("-s may not be inserted");
        }

        // add identity to set; if it is already contained - return null
        if (!setOfIdentities.add(singleIdentity)) {
            return null;
        }
        return create(setOfIdentities);
    }

    /**
     * Deletes a {@link NguyenAccumulatorIdentity} from the accumulated set of {@link NguyenAccumulatorIdentity},
     * updates the {@link NguyenAccumulatorValue}. It returns null if the {@link NguyenAccumulatorIdentity} was not
     * contained in the accumulated set.
     * <p>
     * <p>
     * Since the {@link NguyenAccumulator} does not need the {@link AccumulatorValue} for deletion, the
     * call is delegated to {@link #delete(Set, NguyenAccumulatorIdentity)} without the {@link AccumulatorValue}.
     *
     * @param accumulatorValue {@link NguyenAccumulatorValue}
     * @param setOfIdentities  Set containing all {@link NguyenAccumulatorIdentity}
     * @param singleIdentity   {@link NguyenAccumulatorIdentity} to be deleted
     * @return updated {@link NguyenAccumulatorValue} after deletion of {@link NguyenAccumulatorIdentity}
     */
    @Override
    public AccumulatorValue delete(AccumulatorValue accumulatorValue, Set<NguyenAccumulatorIdentity> setOfIdentities,
                                   NguyenAccumulatorIdentity singleIdentity) {
        return delete(setOfIdentities, singleIdentity);
    }

    /**
     * Deletes a {@link NguyenAccumulatorIdentity} from the accumulated set of {@link NguyenAccumulatorIdentity},
     * updates the {@link NguyenAccumulatorValue}. It returns null if the {@link NguyenAccumulatorIdentity} was not
     * contained in the accumulated set.
     *
     * @param setOfIdentities Set containing all {@link NguyenAccumulatorIdentity}
     * @param singleIdentity  {@link NguyenAccumulatorIdentity} to be deleted
     * @return updated {@link NguyenAccumulatorValue} after deletion of {@link NguyenAccumulatorIdentity}
     */
    public AccumulatorValue delete(Set<NguyenAccumulatorIdentity> setOfIdentities,
                                   NguyenAccumulatorIdentity singleIdentity) {
        isValidSetSize(setOfIdentities);

        // remove identity from set; if identity is not part of the set; return null
        if (!setOfIdentities.remove(singleIdentity)) {
            return null;
        }

        // create new accumulatorValue
        return create(setOfIdentities);
    }

    /**
     * Updates the {@link NguyenWitness} for a {@link NguyenAccumulatorIdentity} after the
     * set of {@link NguyenAccumulatorIdentity} in the {@link NguyenAccumulator} has been changed by one or many
     * operations; namely {@link NguyenAccumulator#delete} and {@link NguyenAccumulator#insert}.
     * <p>
     * Single changes can be calculated more efficiently than with
     * {@link NguyenAccumulator#createWitness}.
     * For multiple changes the updated {@link NguyenWitness} is calculated with
     * {@link NguyenAccumulator#createWitness}.
     *
     * @param oldAccumulatorValue         Old {@link NguyenAccumulatorValue}
     * @param currentAccumulatorValue     current {@link NguyenAccumulatorValue}
     * @param oldAccumulatedSet           Set containing all {@link NguyenAccumulatorIdentity} accumulated in the old
     *                                    {@link DynamicAccumulator} which needs to be updated
     * @param currentAccumulatedSet       Set containing all {@link NguyenAccumulatorIdentity} accumulated in the
     *                                    current
     *                                    {@link DynamicAccumulator}
     * @param singleIdentity              value of {@link NguyenWitness} oldWitnessForSingleIdentity in old and current
     *                                    {@link DynamicAccumulator}s to be updated
     * @param oldWitnessForSingleIdentity {@link NguyenWitness} oldWitnessForSingleIdentity with value singleIdentity in
     *                                    old  and current {@link DynamicAccumulator}s that needs to be updated
     * @return updated {@link NguyenWitness} for the current {@link NguyenAccumulatorValue}
     */
    @Override
    public NguyenWitness update(AccumulatorValue oldAccumulatorValue, AccumulatorValue currentAccumulatorValue,
                                Set<NguyenAccumulatorIdentity> oldAccumulatedSet, Set<NguyenAccumulatorIdentity>
                                        currentAccumulatedSet,
                                NguyenAccumulatorIdentity singleIdentity,
                                AccumulatorWitness oldWitnessForSingleIdentity) {

        if (!currentAccumulatedSet.contains(singleIdentity)) {
            throw new IllegalArgumentException("Identity is not contained in the current accumulated set!");
        }
        NguyenWitness witness;
        if (oldWitnessForSingleIdentity instanceof NguyenWitness) {
            witness = (NguyenWitness) oldWitnessForSingleIdentity;
        } else throw new IllegalArgumentException("Witness is not a NguyenWitness!");

        List<NguyenAccumulatorIdentity> deletedElements = oldAccumulatedSet.stream()
                .filter(old -> !currentAccumulatedSet
                        .contains(old))
                .collect(Collectors
                        .toCollection(ArrayList::new));
        List<NguyenAccumulatorIdentity> insertedElements = currentAccumulatedSet.stream()
                .filter(old -> !oldAccumulatedSet
                        .contains(old))
                .collect(Collectors
                        .toCollection(ArrayList::new));
        if (deletedElements.isEmpty() && insertedElements.isEmpty()) {
            return witness;
        } else {
            if (deletedElements.size() + insertedElements.size() == 1) {
                if (deletedElements.size() == 1) {
                    return updateDelete(currentAccumulatorValue, deletedElements.get(0), singleIdentity, witness);
                } else {
                    return updateInsert(oldAccumulatorValue, insertedElements.get(0), singleIdentity, witness);
                }
            } else {
                return (NguyenWitness) createWitness(currentAccumulatedSet, singleIdentity);
            }
        }
    }

    /**
     * Efficient calculation of tha updated {@link NguyenWitness} after one insert()
     * <p>
     * Computes an updated witness $w_i'$ for the new accumulator value $V'$ that changed due to the insertion of $x'$.
     * The algorithm needs the outdated accumulator value $V$ and outputs $w_i' = V\cdot w_i^{x'-x_i}$
     *
     * @param oldAccumulatorValue         {@link NguyenAccumulatorValue} before single insert()
     * @param insertedSingleIdentity      {@link NguyenAccumulatorValue} after single insert()
     * @param singleIdentity              {@link NguyenAccumulatorIdentity} accumulated in the {@link NguyenAccumulator}
     * @param oldWitnessForSingleIdentity {@link NguyenWitness} for the {@link NguyenAccumulatorIdentity}
     * @return updated {@link NguyenWitness} for the {@link NguyenAccumulatorIdentity} after one insert()
     */
    private NguyenWitness updateInsert(AccumulatorValue oldAccumulatorValue, NguyenAccumulatorIdentity
            insertedSingleIdentity, NguyenAccumulatorIdentity singleIdentity,
                                       AccumulatorWitness oldWitnessForSingleIdentity) {
        if (!(oldAccumulatorValue instanceof NguyenAccumulatorValue)) {
            throw new IllegalArgumentException("AccumulatorValue is not a NguyenAccumulatorValue!");
        }
        if (!(oldWitnessForSingleIdentity instanceof NguyenWitness)) {
            throw new IllegalArgumentException("Witness is not a NguyenWitness!");
        }
        GroupElement accumulatorValue = ((NguyenAccumulatorValue) oldAccumulatorValue).getValue();
        GroupElement oldWitness = ((NguyenWitness) oldWitnessForSingleIdentity).getValue();
        Zp.ZpElement identityDifference = insertedSingleIdentity.getIdentity().add(singleIdentity.getIdentity().neg());
        GroupElement witPower = oldWitness.pow(identityDifference);
        GroupElement result = accumulatorValue.op(witPower);
        return new NguyenWitness(result.compute());
    }

    /**
     * Efficient calculation of tha updated {@link NguyenWitness} after one delete()
     * <p>
     * Computes an updated witness $w_i'$ for the accumulator value $V'$ that changed due to the deletion of $x'$. It
     * outputs $w_i' = (\frac{w_i}{V'})^{(x'-x_i)^{-1}}$
     *
     * @param currentAccumulatorValue     {@link NguyenAccumulatorValue} after single delete()
     * @param deletedSingleIdentity       {@link NguyenAccumulatorValue} deleted in single delete()
     * @param singleIdentity              {@link NguyenAccumulatorIdentity} accumulated in the {@link NguyenAccumulator}
     * @param oldWitnessForSingleIdentity {@link NguyenWitness} for the {@link NguyenAccumulatorIdentity}
     * @return updated {@link NguyenWitness} for the {@link NguyenAccumulatorIdentity} after one delete()
     */
    private NguyenWitness updateDelete(AccumulatorValue currentAccumulatorValue, NguyenAccumulatorIdentity
            deletedSingleIdentity, NguyenAccumulatorIdentity singleIdentity,
                                       AccumulatorWitness oldWitnessForSingleIdentity) {

        if (!(currentAccumulatorValue instanceof NguyenAccumulatorValue)) {
            throw new IllegalArgumentException("AccumulatorValue is not a NguyenAccumulatorValue!");
        }
        if (!(oldWitnessForSingleIdentity instanceof NguyenWitness)) {
            throw new IllegalArgumentException("Witness is not a NguyenWitness!");
        }
        GroupElement accumulatorValue = ((NguyenAccumulatorValue) currentAccumulatorValue).getValue();
        GroupElement oldWitness = ((NguyenWitness) oldWitnessForSingleIdentity).getValue();
        Zp.ZpElement identityDifference = deletedSingleIdentity.getIdentity().add(singleIdentity.getIdentity().neg());
        Zp.ZpElement identityDifferenceInverse = identityDifference.inv();
        GroupElement quotient = oldWitness.op(accumulatorValue.inv());
        GroupElement result = quotient.pow(identityDifferenceInverse);
        return new NguyenWitness(result.compute());
    }


    private boolean isValidSetSize(Set<NguyenAccumulatorIdentity> setOfIdentities) {
        if (setOfIdentities.size() > pp.getUpperBoundForAccumulatableIdentities().intValue()) {
            throw new IllegalArgumentException("Too many identities for this accumulator.");
        }
        if (setOfIdentities.isEmpty()) {
            throw new IllegalArgumentException("The given set is empty.");
        }
        return true;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NguyenAccumulator that = (NguyenAccumulator) o;
        return Objects.equals(pp, that.pp) &&
                Objects.equals(accumulatorValue, that.accumulatorValue) &&
                Objects.equals(identitySet, that.identitySet);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pp, accumulatorValue, identitySet);
    }

    public NguyenAccumulatorPublicParameters getPp() {
        return pp;
    }

    private void setPp(NguyenAccumulatorPublicParameters pp) {
        this.pp = pp;
    }

    public NguyenAccumulatorValue getAccumulatorValue() {
        return accumulatorValue;
    }

    private void setAccumulatorValue(NguyenAccumulatorValue accumulatorValue) {
        this.accumulatorValue = accumulatorValue;
    }

    public Set<NguyenAccumulatorIdentity> getIdentitySet() {
        return identitySet;
    }

    private void setIdentitySet(Set<NguyenAccumulatorIdentity> identitySet) {
        this.identitySet = identitySet;
    }
}
