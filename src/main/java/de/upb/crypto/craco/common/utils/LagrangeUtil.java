package de.upb.crypto.craco.common.utils;

import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.Set;

/**
 * Definition 2.9 in the paper: Lagrange coefficient.
 *
 * @author Marius Dransfeld
 */
public final class LagrangeUtil {
    private LagrangeUtil() {

    }

    /**
     * Compute the Lagrange coefficient
     *
     * @param i
     * @param S
     * @param x
     * @return
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
     * Compute the Lagrange coefficient
     *
     * @param i
     * @param S
     * @param x
     * @param field
     * @return
     */
    public static BigInteger computeCoefficient(BigInteger i, Set<BigInteger> S, BigInteger x,
                                                Zp field) {
        return computeCoefficient(field.createZnElement(i), S, field.createZnElement(x)).getInteger();
    }
}
