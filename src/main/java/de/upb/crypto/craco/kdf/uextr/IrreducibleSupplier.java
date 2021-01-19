package de.upb.crypto.craco.kdf.uextr;

import de.upb.crypto.math.interfaces.structures.RingElement;
import de.upb.crypto.math.structures.polynomial.PolynomialRing;
import de.upb.crypto.math.structures.polynomial.PolynomialRing.Polynomial;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * Provides binary efficient irreducible polynomials in Zp2 (Trinomials or
 * Pentanomials) via a table lookup.
 * ({@literal http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.365.1806&rep=rep1&type=pdf})
 *
 *
 */
public class IrreducibleSupplier {

    private static final Zp zp = new Zp(BigInteger.valueOf(2));

    private static final ZpElement ONE = zp.createZnElement(BigInteger.ONE);
    ;

    private static final ZpElement ZERO = zp.createZnElement(BigInteger.ZERO);

    private static final PolynomialRing baseRing = new PolynomialRing(zp);

    private static final String PATH = "src/main/resources/listOfIrreducible";

    private IrreducibleSupplier() {
    }

    public static Polynomial getIrreducible(int degree) {
        String poly = "";
        if (degree > 10000 || degree < 2) {
            throw new IllegalArgumentException("Only polynomials of degree 2 - 10000 can be provided");
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(PATH));) {
            // list has 10 elements per line; however the counting starts at 1
            // i.e. line 2 has the polynomials 11-20
            int lineNumber = (int) Math.floor(((double) degree - 1) / 10) + 1;
            int lineCounter = 1;
            while (lineCounter != lineNumber) {
                @SuppressWarnings("unused")
                String nextLine = reader.readLine();
                lineCounter++;
            }
            String line = reader.readLine();
            reader.close();
            // the polynomials are separated using a whitespace
            Scanner lineScanner = new Scanner(line);
            lineScanner.useDelimiter(" ");

            boolean found = false;

            while (lineScanner.hasNext() && !found) {
                poly = lineScanner.next();
                if (poly.startsWith(degree + "")) {
                    found = true;
                }
            }
            lineScanner.close();
            if (!found) {
                throw new IllegalStateException("Something went wrong! Couldn't read the desired polynomial");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // convert the comma separated coefficients to a polynomial
        try (Scanner polyScanner = new Scanner(poly);) {
            polyScanner.useDelimiter(",");

            List<Integer> polyList = new ArrayList<>();

            while (polyScanner.hasNextInt()) {
                polyList.add(polyScanner.nextInt());
            }
            polyScanner.close();
            List<RingElement> coefficients = new ArrayList<>(degree + 1);

            for (int i = 0; i <= degree; i++) {
                if (polyList.contains(i)) {
                    coefficients.add(ONE);
                } else {
                    coefficients.add(ZERO);
                }
            }
            return baseRing.new Polynomial(coefficients);
        }
    }
}
