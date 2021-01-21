package de.upb.crypto.craco.common.utils;

import de.upb.crypto.math.random.interfaces.RandomGenerator;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;

/**
 * Polynomial over a prime field.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens
 */
public final class PrimeFieldPolynomial implements Cloneable {
    private ZpElement[] coefficients;
    private Zp field;

    /**
     * Creates a new polynomial over the given prime field.
     *
     * @param field  prime field
     * @param degree degree of the polynomial
     */
    public PrimeFieldPolynomial(Zp field, int degree) {
        coefficients = new ZpElement[degree + 1];
        this.field = field;
    }

    /**
     * Degree of this polynomial, i.e. number of coefficients - 1.
     *
     * @return degree of polynomial
     */
    public int getDegree() {
        return coefficients.length - 1;
    }

    /**
     * Set {@link ZpElement} coefficient at index i.
     *
     * @param coefficient new coefficient
     * @param i           index
     */
    public void setCoefficient(ZpElement coefficient, int i) {
        coefficients[i] = coefficient;
    }

    /**
     * Set {@link BigInteger} coefficient at index i.
     *
     * @param coefficient new coefficient
     * @param i           index
     */
    public void setCoefficient(BigInteger coefficient, int i) {
        coefficients[i] = field.createZnElement(coefficient);
    }

    /**
     * Get coefficient at index i.
     *
     * @param i index
     * @return corresponding coefficient
     */
    public ZpElement getCoefficient(int i) {
        return coefficients[i];
    }

    /**
     * Evaluates the polynomial at value x, returning a {@link ZpElement}.
     *
     * @param x value to evaluate the polynomial at
     * @return result of evaluation as a {@link ZpElement}
     */
    public ZpElement evaluate(ZpElement x) {
        ZpElement result = field.getZeroElement();
        for (int i = 0; i < coefficients.length; i++) {
            ZpElement x_i = (ZpElement) x.pow(BigInteger.valueOf(i));
            ZpElement a_x_i = x_i.mul(coefficients[i]);
            result = result.add(a_x_i);
        }
        return result;
    }

    /**
     * Evaluates the polynomial at value x, returning a {@link BigInteger}.
     *
     * @param x value to evaluate the polynomial at
     * @return result of evaluation as a {@link BigInteger}
     */
    public BigInteger evaluate(BigInteger x) {
        return evaluate(field.createZnElement(x)).getInteger();
    }

    /**
     * Assigns random non-zero values to all coefficients.
     *
     * @param rng random number generator
     */
    public void createRandom(RandomGenerator rng) {
        ZpElement zero = field.getZeroElement();
        for (int i = 0; i < coefficients.length; i++) {
            // generate random non-zero coefficient
            do {
                coefficients[i] = field.getUniformlyRandomElement();
            } while (coefficients[i].equals(zero));
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj instanceof ZpElement) {
            PrimeFieldPolynomial p = (PrimeFieldPolynomial) obj;
            if (!p.field.equals(field)) {
                return false;
            }
            if (coefficients.length != p.coefficients.length) {
                return false;
            }
            for (int i = 0; i < coefficients.length; i++) {
                if (!coefficients[i].equals(p.coefficients[i])) {
                    return false;
                }
            }
            return true;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = coefficients.length - 1; i >= 0; i--) {
            switch (i) {
                case 0:
                    sb.append(coefficients[i].toString());
                    break;
                case 1:
                    sb.append(coefficients[i].toString() + "*x + ");
                    break;
                default:
                    sb.append(coefficients[i].toString() + "*x^" + i + " + ");
                    break;
            }

        }
        return sb.toString();
    }

    @Override
    public PrimeFieldPolynomial clone() throws CloneNotSupportedException {
        PrimeFieldPolynomial clone = new PrimeFieldPolynomial(field, getDegree());
        for (int i = 0; i < coefficients.length; i++) {
            clone.setCoefficient(coefficients[i], i);
        }
        return clone;
    }
}
