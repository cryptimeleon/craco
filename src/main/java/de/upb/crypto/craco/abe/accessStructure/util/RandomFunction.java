package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.ArrayList;

/**
 * Represents a random polynomial, where only the value at position 0 is set.
 * This is for example used in Shamir secret sharing
 *
 * @author pschleiter
 */
public class RandomFunction {

    /**
     * List of coefficients
     */
    private ArrayList<ZpElement> values = new ArrayList<>();
    /** */
    private Zp zPField;

    /**
     * Creates a new random polynomial of degree <code>deg</code> over the
     * <code>field</code>. The value for position zero is <code>zeroValue</code> .
     *
     * @param deg      - degree of the created polynomial
     * @param zeroValue - value for position zero
     * @param zpField   - field over that the polynomial is defined
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
