package de.upb.crypto.craco.common.utils;

import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.Set;

/**
 * Utility class for computing Lagrange coefficient/evaluating Lagrange basis polynomials.
 *
 * @author Marius Dransfeld
 */
public final class LagrangeUtil {
    private LagrangeUtil() {

    }

    /**
     * Compute the Lagrange coefficient {@code l_j(x)}.
     *
     * @param i jth x coordinate
     * @param S set of x coordinates
     * @param x x coordinate to evaluate the lagrange basis polynomial at
     * @return the lagrange basis polynomial evaluated at coordinate {@code x}.
     */
    public static ZpElement computeCoefficient(ZpElement i, Set<BigInteger> S,
                                               ZpElement x) {
        ZpElement result = i.getStructure().getOneElement();
        for (BigInteger jk : S) {
            ZpElement j = i.getStructure().createZnElement(jk);
            if (j.equals(i)) {
                continue;
            }
            ZpElement numerator = (ZpElement) x.sub(j);
            ZpElement denominator = (ZpElement) i.sub(j);

            result = result.mul(numerator.div(denominator));
        }
        return result;
    }

    /**
     * Compute the Lagrange coefficient {@code l_j(x)} over the specified field.
     *
     * @param i jth x coordinate
     * @param S set of x coordinates
     * @param x x coordinate to evaluate the lagrange basis polynomial at
     * @param field the field to do the computation over
     * @return the lagrange basis polynomial evaluated at coordinate {@code x} in the given field
     */
    public static BigInteger computeCoefficient(BigInteger i, Set<BigInteger> S, BigInteger x,
                                                Zp field) {
        return computeCoefficient(field.createZnElement(i), S, field.createZnElement(x)).getInteger();
    }
}
