package org.cryptimeleon.craco.accumulator.nguyen;

import org.cryptimeleon.craco.accumulator.AccumulatorDigest;
import org.cryptimeleon.craco.accumulator.AccumulatorScheme;
import org.cryptimeleon.craco.accumulator.AccumulatorWitness;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.hash.annotations.UniqueByteRepresented;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.groups.elliptic.type3.bn.BarretoNaehrigBilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.polynomial.PolynomialRing;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * An implementation of the Nguyen accumulator (https://eprint.iacr.org/2005/123). <br>
 * To instantiate, let a trusted party run {@link #setup(BilinearGroup, int)}, then disseminate the {@linkplain Representation} of the resulting {@linkplain NguyenAccumulatorScheme} to other parties.
 */
public class NguyenAccumulatorScheme implements AccumulatorScheme<Zn.ZnElement>, UniqueByteRepresentable {
    @Represented
    private BilinearGroup bilinearGroup;

    @UniqueByteRepresented
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g;

    @UniqueByteRepresented
    @Represented(restorer = "bilinearGroup::getG2")
    private GroupElement g_Tilde;

    @UniqueByteRepresented
    @Represented(restorer = "bilinearGroup::getG2")
    private GroupElement g_Tilde_Power_S;

    /**
     * t.get(i) = g.pow(s.pow(i))
     */
    @UniqueByteRepresented
    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElementVector t;

    public NguyenAccumulatorScheme(BilinearGroup bilinearGroup, GroupElement g, GroupElement g_Tilde, GroupElement g_Tilde_Power_S, GroupElementVector t) {
        this.bilinearGroup = bilinearGroup;
        this.g = g;
        this.g_Tilde = g_Tilde;
        this.g_Tilde_Power_S = g_Tilde_Power_S;
        this.t = t;
    }

    public NguyenAccumulatorScheme(Representation repr) {
        ReprUtil.deserialize(this, repr);
    }

    public static NguyenAccumulatorScheme setup(BilinearGroup bilinearGroup, int size) {
        // Generate public parameters
        GroupElement g = bilinearGroup.getG1().getUniformlyRandomNonNeutral().compute();
        GroupElement g_Tilde = bilinearGroup.getG2().getUniformlyRandomNonNeutral().compute();
        Zn zn = bilinearGroup.getZn();
        Zn.ZnElement s = zn.getUniformlyRandomElement();
        GroupElement g_Tilde_Power_S = g_Tilde.pow(s).compute();

        //t.get(i) = g^(s^i)
        GroupElementVector t = GroupElementVector.iterate(g, h -> h.pow(s), size+1);

        return new NguyenAccumulatorScheme(bilinearGroup, g, g_Tilde, g_Tilde_Power_S, t);
    }


    public static NguyenAccumulatorScheme setup(int securityParameter, int size) {
        return setup(new BarretoNaehrigBilinearGroup(securityParameter), size);
    }

    /**
     * Computes g^{poly}, where poly = prod_[i in inverseOfRootsOfPolynomial] (x+i)
     */
    private GroupElement computeGPowPoly(Stream<? extends Zn.ZnElement> inverseOfRootsOfPolynomial) {
        // create Polynomial
        PolynomialRing polynomialRing = new PolynomialRing(bilinearGroup.getZn());

        PolynomialRing.Polynomial polynomial = inverseOfRootsOfPolynomial
                .map(rootInverse -> polynomialRing.getX().add(rootInverse))
                .reduce(polynomialRing.getOneElement(), PolynomialRing.Polynomial::mul);

        // get coefficients
        RingElementVector coefficients = polynomial.getCoefficientVector().pad(bilinearGroup.getZn().getZeroElement(), t.length());

        // calculate product
        return t.innerProduct(coefficients);
    }

    /**
     * Computes g^{poly}, where poly = prod_[i in inverseOfRootsOfPolynomial] (x+i)
     */
    private GroupElement computeGPowPoly(Collection<? extends Zn.ZnElement> inverseOfRootsOfPolynomial) {
        return computeGPowPoly(inverseOfRootsOfPolynomial.stream());
    }

    @Override
    public NguyenDigest createDigest(Collection<? extends Zn.ZnElement> setOfValues) {
        if (setOfValues.size() > getMaxNumAccumulatedValues()) {
            throw new IllegalArgumentException("Too many values for this accumulator.");
        }

        return new NguyenDigest(computeGPowPoly(setOfValues));
    }

    @Override
    public NguyenWitness createWitness(AccumulatorDigest digest, Collection<? extends Zn.ZnElement> setOfAccumulatedValues, Zn.ZnElement valueToComputeWitnessFor) {
        return createWitness(setOfAccumulatedValues, valueToComputeWitnessFor);
    }

    public NguyenWitness createWitness(Collection<? extends Zn.ZnElement> setOfAccumulatedValues, Zn.ZnElement valueToComputeWitnessFor) {
        return new NguyenWitness(computeGPowPoly(setOfAccumulatedValues.stream().filter(v -> !v.equals(valueToComputeWitnessFor))));
    }

    @Override
    public boolean verify(AccumulatorDigest accumulatorDigest, Zn.ZnElement singleValue, AccumulatorWitness witnessForSingleValue) {
        BilinearMap e = bilinearGroup.getBilinearMap();
        return e.apply(((NguyenDigest) accumulatorDigest).getDigest(), g_Tilde)
                .equals(e.apply(((NguyenWitness) witnessForSingleValue).getWitness(), g_Tilde_Power_S.op(g_Tilde.pow(singleValue))));
    }


    @Override
    public NguyenWitness updateWitness(AccumulatorDigest oldDigest, AccumulatorDigest newDigest, Collection<? extends Zn.ZnElement> oldAccumulatedSet, Collection<? extends Zn.ZnElement> newAccumulatedSet, Zn.ZnElement valueToComputeWitnessFor, AccumulatorWitness oldWitnessToBeUpdated) {
        if (!newAccumulatedSet.contains(valueToComputeWitnessFor)) {
            throw new IllegalArgumentException("Desired value is not contained in the current accumulated set");
        }

        GroupElement oldAcc = ((NguyenDigest) oldDigest).getDigest();
        GroupElement newAcc = ((NguyenDigest) newDigest).getDigest();
        GroupElement oldWitness = ((NguyenWitness) oldWitnessToBeUpdated).getWitness();

        if (newAccumulatedSet.size() == oldAccumulatedSet.size() + 1 && newAccumulatedSet.containsAll(oldAccumulatedSet)) {
            Zn.ZnElement insertedElement = newAccumulatedSet.stream().filter(x -> !oldAccumulatedSet.contains(x)).findAny().get();
            return new NguyenWitness(oldAcc.op(oldWitness.pow(insertedElement.sub(valueToComputeWitnessFor))).compute());
        } else if (newAccumulatedSet.size() == oldAccumulatedSet.size() - 1 && oldAccumulatedSet.containsAll(newAccumulatedSet)) {
            Zn.ZnElement deletedElement = oldAccumulatedSet.stream().filter(x -> !newAccumulatedSet.contains(x)).findAny().get();
            return new NguyenWitness(oldWitness.op(newAcc.inv()).pow(deletedElement.sub(valueToComputeWitnessFor).inv()).compute());
        }

        return createWitness(newAccumulatedSet, valueToComputeWitnessFor);
    }

    @Override
    public Integer getMaxNumAccumulatedValues() {
        return t.length()-1;
    }

    @Override
    public NguyenWitness restoreWitness(Representation repr) {
        return new NguyenWitness(repr, bilinearGroup.getG1());
    }

    @Override
    public AccumulatorDigest restoreDigest(Representation repr) {
        return new NguyenDigest(repr, bilinearGroup.getG1());
    }

    @Override
    public Zn.ZnElement restoreAccumulatedValue(Representation repr) {
        return bilinearGroup.getZn().getElement(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NguyenAccumulatorScheme that = (NguyenAccumulatorScheme) o;
        return bilinearGroup.equals(that.bilinearGroup) && g.equals(that.g) && g_Tilde.equals(that.g_Tilde) && g_Tilde_Power_S.equals(that.g_Tilde_Power_S) && t.equals(that.t);
    }

    @Override
    public int hashCode() {
        return Objects.hash(g_Tilde_Power_S);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
