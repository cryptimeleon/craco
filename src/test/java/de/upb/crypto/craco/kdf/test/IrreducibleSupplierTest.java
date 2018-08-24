package de.upb.crypto.craco.kdf.test;

import de.upb.crypto.craco.kdf.uextr.IrreducibleSupplier;
import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.structures.polynomial.PolynomialRing;
import de.upb.crypto.math.structures.polynomial.PolynomialRing.Polynomial;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class IrreducibleSupplierTest {


    @Test
    public void testTrinomial() {
        Zp zp = new Zp(BigInteger.valueOf(2));

        ZpElement ONE = zp.createZnElement(BigInteger.ONE);

        ZpElement ZERO = zp.createZnElement(BigInteger.ZERO);

        PolynomialRing baseRing = new PolynomialRing(zp);

        //poly is 4431,47
        List<RingElement> coefficients = new ArrayList<>(4432);

        for (int i = 0; i <= 4432; i++) {
            if (i == 4431 || i == 47) {
                coefficients.add(ONE);
            } else {
                coefficients.add(ZERO);
            }
        }
        Polynomial expected = baseRing.new Polynomial(coefficients);
        Polynomial result = IrreducibleSupplier.getIrreducible(4431);
        Assert.assertTrue(expected.equals(result));
    }

    @Test
    public void testPentanomial() {
        Zp zp = new Zp(BigInteger.valueOf(2));

        ZpElement ONE = zp.createZnElement(BigInteger.ONE);

        ZpElement ZERO = zp.createZnElement(BigInteger.ZERO);

        PolynomialRing baseRing = new PolynomialRing(zp);

        //poly is 9787,20,13,9
        List<RingElement> coefficients = new ArrayList<>(9788);

        for (int i = 0; i <= 9788; i++) {
            if (i == 9787 || i == 20 || i == 13 || i == 9) {
                coefficients.add(ONE);
            } else {
                coefficients.add(ZERO);
            }
        }
        Polynomial expected = baseRing.new Polynomial(coefficients);
        Polynomial result = IrreducibleSupplier.getIrreducible(9787);
        Assert.assertTrue(expected.equals(result));
    }
}
