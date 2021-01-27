package de.upb.crypto.craco.secretsharing.shamir;

import de.upb.crypto.craco.secretsharing.LinearSecretSharing;
import de.upb.crypto.craco.secretsharing.accessstructure.exception.NoSatisfyingSet;
import de.upb.crypto.craco.secretsharing.accessstructure.exception.WrongAccessStructureException;
import de.upb.crypto.craco.common.policy.Policy;
import de.upb.crypto.craco.common.policy.ThresholdPolicy;
import de.upb.crypto.craco.secretsharing.ThresholdTreeSecretSharing;
import de.upb.crypto.math.structures.rings.RingElement;
import de.upb.crypto.math.structures.rings.polynomial.PolynomialRing;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Shamir's secret sharing scheme is a linear secret sharing scheme based on polynomial interpolation.
 * <p>
 * Assume s is the secret to be shared. Based on the threshold t of the given {@link ThresholdPolicy} a
 * {@link PolynomialRing.Polynomial} P(x) of degree t-1 is computed,
 * such that \(P(0)=s\).
 * <p>
 * The shares \((i, s_i = P(i))\) correspond to data points on the polynomial therefore any set \(S\) of shares
 * with \(|S| >= t\) can be used to uniquely determine the original polynomial using interpolation and therefore
 * reconstruct
 * the secret.
 * <p>
 * The secret is only shared among the direct children of the given {@link ThresholdPolicy}.
 * To share a secret among all {@link ThresholdPolicy} in a hierarchy of {@link Policy}s use
 * {@link ThresholdTreeSecretSharing}.
 */
public class ShamirSecretSharing implements LinearSecretSharing<Policy> {
    private ThresholdPolicy policy;
    private Zp field;

    /**
     * Create a new {@link ShamirSecretSharing} instance
     *
     * @param policy {@link ThresholdPolicy} among which children a secret shall be shared
     * @param field  {@link Zp} over which the secret shall be shared
     */
    public ShamirSecretSharing(ThresholdPolicy policy, Zp field) {
        this.policy = policy;
        this.field = field;
    }

    @Override
    public Map<Integer, Zp.ZpElement> getShares(Zp.ZpElement secret) throws WrongAccessStructureException {
        if (secret == null || !field.equals(secret.getStructure())) {
            throw new WrongAccessStructureException(secret + " can not be shared over " + field);
        }

        int numberOfChildren = policy.getChildren().size();

        //The Polynomial shall be reconstructed using t data points (shares).
        //Therefore we construct a polynomial of degree t-1 using t coefficients.
        //To ensure P(0)=s we fix the first data point (coeff for x^0) to s and choose the remaining at random.
        RingElement[] coefficients = new RingElement[policy.getThreshold()];
        coefficients[0] = secret;
        for (int i = 1; i < coefficients.length; i++) {
            coefficients[i] = field.getUniformlyRandomUnit();
        }
        PolynomialRing.Polynomial polynomial = PolynomialRing.getPoly(coefficients);

        //The shares are determined by evaluating their respective share id on the constructed polynomial
        Map<Integer, Zp.ZpElement> shares = new HashMap<>(numberOfChildren);
        for (int i = 1; i <= numberOfChildren; i++) {
            Zp.ZpElement element = field.createZnElement(BigInteger.valueOf(i));
            shares.put(i, (Zp.ZpElement) polynomial.evaluate(element));
        }

        return shares;
    }

    @Override
    public Map<Integer, Zp.ZpElement> getSolvingVector(
            Set<? extends Policy> setOfShareReceivers) throws NoSatisfyingSet, WrongAccessStructureException {
        if (!isQualified(setOfShareReceivers)) {
            throw new NoSatisfyingSet();
        }

        return getSolvingVector(getSharesOfReceivers(setOfShareReceivers));
    }


    /**
     * Calculates the coefficients of the Lagrange interpolation based on the given indices (x_i).
     *
     * <p>
     * The x_i correspond to the the x-values of the data set retrieved by {@link LinearSecretSharing#getShares}.
     * To evaluate the interpolated polynomial at the 0, one needs to compute
     * <p>
     * \sum s_i * a_i
     * <p>
     * for the a_i output by this function.
     * </p>
     *
     * @param shareReceiverIds index set of shares to use during interpolation
     * @return a mapping (i -> a_i) s.t. a_i = \prod\limits_{i \neq j}(\frac{-x_j}{x_i-x_j})
     */
    private Map<Integer, Zp.ZpElement> getSolvingVector(Collection<Integer> shareReceiverIds) throws NoSatisfyingSet,
            WrongAccessStructureException {
        Map<Integer, Zp.ZpElement> solvingVector = new HashMap<>(shareReceiverIds.size());
        for (int i : shareReceiverIds) {
            Zp.ZpElement numerator = field.getOneElement();
            Zp.ZpElement denominator = field.getOneElement();
            for (int j : shareReceiverIds) {
                if (i == j)
                    continue;

                Zp.ZpElement xi = field.createZnElement(BigInteger.valueOf(i));
                Zp.ZpElement xj = field.createZnElement(BigInteger.valueOf(j));
                numerator = numerator.mul(xj.neg());
                denominator = denominator.mul(xi.add(xj.neg()));
            }
            solvingVector.put(i, numerator.mul(denominator.inv()));
        }
        return solvingVector;
    }

    @Override
    public Map<Integer, Policy> getShareReceiverMap() {
        int numberOfChildren = policy.getChildren().size();
        Map<Integer, Policy> shareReceiver = new HashMap<>(numberOfChildren);
        for (int i = 1; i <= numberOfChildren; i++) {
            shareReceiver.put(i, policy.getChildren().get(i - 1));
        }
        return shareReceiver;
    }

    @Override
    public boolean isQualified(Set<? extends Policy> setOfShareReceivers) throws WrongAccessStructureException {
        Set<Integer> shares = getSharesOfReceivers(setOfShareReceivers);
        return shares.size() >= policy.getThreshold();
    }

    @Override
    public Zp getSharedRing() {
        return field;
    }

    @Override
    public Map<Integer, Zp.ZpElement> completeShares(Zp.ZpElement secret, Map<Integer, Zp.ZpElement> partialShares) {
        int numberOfShares = policy.getChildren().size();
        //We need one less coefficient as shares needed, as coeff[0] = secret
        int numberOfAdditionalCoeff = policy.getThreshold() - partialShares.size() - 1;

        Map<Integer, Zp.ZpElement> fullShares = new HashMap<>(partialShares);

        //Collect all indices currently not covered by the given set of partial shares
        //as we can only pick values for those.
        //This assumes that all indices are enumerated 1,...,n
        int[] missingIndices = IntStream.rangeClosed(1, numberOfShares)
                .filter(index -> !partialShares.containsKey(index))
                .toArray();

        //guess enough points for interpolation
        for (int i = 0; i < numberOfAdditionalCoeff; i++) {
            Zp.ZpElement element = field.getUniformlyRandomUnit();
            fullShares.put(missingIndices[i], element);
        }

        //Calculate the data points of the polynomial in regard of the given and guessed indices
        Map<Zp.ZpElement, Zp.ZpElement> dataPoints = collectDataPointsFromShares(fullShares);

        dataPoints.put(field.getZeroElement(), secret);
        PolynomialRing.Polynomial polynomial = PolynomialRing.getPoly(dataPoints, policy.getThreshold() - 1);

        //Collect all indices currently not covered by the given set of shares
        //This assumes that all indices are enumerated 1,...,n
        missingIndices = IntStream.rangeClosed(1, numberOfShares)
                .filter(index -> !fullShares.containsKey(index))
                .toArray();

        //Complete the i -> s_i mapping using the constructed polynomial
        for (int i : missingIndices) {
            Zp.ZpElement element = field.createZnElement(BigInteger.valueOf(i));
            fullShares.put(i, (Zp.ZpElement) polynomial.evaluate(element));
        }
        return fullShares;
    }

    private Map<Zp.ZpElement, Zp.ZpElement> collectDataPointsFromShares(Map<Integer, Zp.ZpElement> shares) {
        return shares.entrySet().stream()
                .collect(Collectors.toMap(
                        entry -> field.createZnElement(BigInteger.valueOf(entry.getKey())),
                        Map.Entry::getValue));
    }

    @Override
    public boolean checkShareConsistency(Zp.ZpElement secret, Map<Integer, Zp.ZpElement> shares) {
        if (shares.size() < policy.getThreshold()) {
            throw new IllegalArgumentException("Not enough shares to reconstruct secret");
        }

        //Take any minimal set (we only need t many shares for reconstruction)
        Map<Integer, Zp.ZpElement> minimalQualifiedShares = shares.entrySet().stream()
                .limit(policy.getThreshold())
                .collect(Collectors
                        .toMap(Map.Entry::getKey,
                                Map.Entry::getValue));


        //Verify that the reconstruction worked
        Zp.ZpElement reconstructedSecret = reconstruct(minimalQualifiedShares);
        if (!reconstructedSecret.equals(secret)) {
            return false;
        }

        //Interpolate the polynomial from the chosen set of qualified shares
        Map<Zp.ZpElement, Zp.ZpElement> dataPoints = collectDataPointsFromShares(minimalQualifiedShares);

        PolynomialRing.Polynomial polynomial = PolynomialRing.getPoly(dataPoints, policy.getThreshold() - 1);

        // Verify that the (i, s_i) match the given shares
        for (Map.Entry<Integer, Zp.ZpElement> entry : shares.entrySet()) {
            Zp.ZpElement element = field.createZnElement(BigInteger.valueOf(entry.getKey()));
            Zp.ZpElement interpolation = (Zp.ZpElement) polynomial.evaluate(element);
            if (!interpolation.equals(entry.getValue())) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ShamirSecretSharing that = (ShamirSecretSharing) o;
        return Objects.equals(policy, that.policy) &&
                Objects.equals(field, that.field);
    }

    @Override
    public int hashCode() {
        return Objects.hash(policy, field);
    }
}

