package de.upb.crypto.craco.common.utils;

import de.upb.crypto.math.random.interfaces.RandomGenerator;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;

/**
 * Polynom over a prime field.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens
 */
public final class PrimeFieldPolynom implements Cloneable {
    private ZpElement[] coefficients;
    private Zp field;

    /**
     * creates a new polynom over the given prime field.
     *
     * @param field  prime field
     * @param degree degree of the polynom
     */
    public PrimeFieldPolynom(Zp field, int degree) {
        coefficients = new ZpElement[degree + 1];
        this.field = field;
    }

    /**
     * Degree of this polynom, i.e. number of coefficients -1.
     *
     * @return degree of polynom
     */
    public int getDegree() {
        return coefficients.length - 1;
    }

    /**
     * set coefficient at index i.
     *
     * @param coefficient
     * @param i           index
     */
    public void setCoefficient(ZpElement coefficient, int i) {
        coefficients[i] = coefficient;
    }

    /**
     * set coefficient at index i.
     *
     * @param coefficient
     * @param i           index
     */
    public void setCoefficient(BigInteger coefficient, int i) {
        coefficients[i] = field.createZnElement(coefficient);
    }

    /**
     * get coefficient at index i.
     *
     * @param i index
     * @return
     */
    public ZpElement getCoefficient(int i) {
        return coefficients[i];
    }

    /**
     * Evaluates the polynom at point x.
     *
     * @param x
     * @return
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
     * Evaluates the polynom at point x.
     *
     * @param x
     * @return
     */
    public BigInteger evaluate(BigInteger x) {
        return evaluate(field.createZnElement(x)).getInteger();
    }

    /**
     * assigns random non-zero values to all coefficients.
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
            PrimeFieldPolynom p = (PrimeFieldPolynom) obj;
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
    public PrimeFieldPolynom clone() throws CloneNotSupportedException {
        PrimeFieldPolynom clone = new PrimeFieldPolynom(field, getDegree());
        for (int i = 0; i < coefficients.length; i++) {
            clone.setCoefficient(coefficients[i], i);
        }
        return clone;
    }
}
