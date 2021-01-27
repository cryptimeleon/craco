package de.upb.crypto.craco.secretsharing.accessstructure.utils;

import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.ArrayList;

/**
 * Represents a random polynomial, where only the value at position 0 is set.
 * This is for example used in Shamir secret sharing
 */
public class RandomFunction {

    /**
     * List of coefficients
     */
    private final ArrayList<ZpElement> values = new ArrayList<>();
    /** */
    private final Zp zPField;

    /**
     * Creates a new random polynomial of degree <code>deg</code> over the
     * <code>field</code>. The value of the zeroth degree coefficient is <code>zeroValue</code> .
     *
     * @param deg       degree of the created polynomial
     * @param zeroValue value of zeroth degree coefficient
     * @param zpField   field over which the polynomial is defined
     */
    public RandomFunction(BigInteger deg, ZpElement zeroValue, Zp zpField) {
        this.zPField = zpField;

        values.add(zeroValue);

        if (!deg.equals(BigInteger.ZERO)) {
            // generate coefficients for X^i i<deg
            BigInteger counter = BigInteger.ONE;
            while (!(counter.equals(deg))) {
                values.add(zpField.getUniformlyRandomElement());
                counter = counter.add(BigInteger.ONE);
            }

            // generate the coefficient for X^deg, which has to be not equal
            // zero
            ZpElement value;
            do {
                value = zpField.getUniformlyRandomElement();
            } while (value.isZero());
            values.add(value);

        }

    }

    /**
     * Return the value of the polynomial evaluated at <code>x</code>. Applies
     * Horner scheme.
     *
     * @param x position to evaluate
     * @return result of evaluation at position <code>x</code>
     */
    public ZpElement getValueFor(BigInteger x) {
        ZpElement xe = zPField.createZnElement(x);
        ZpElement result = zPField.getZeroElement();

        for (int i = values.size(); i > 0; i--) {
            result = values.get(i - 1).add(result.mul(xe));

        }

        return result;
    }

}
