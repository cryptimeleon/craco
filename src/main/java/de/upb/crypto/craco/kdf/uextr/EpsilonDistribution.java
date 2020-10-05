package de.upb.crypto.craco.kdf.uextr;

import de.upb.crypto.math.serialization.*;
import de.upb.crypto.math.structures.polynomial.PolynomialRing;
import de.upb.crypto.math.structures.polynomial.PolynomialRing.Polynomial;
import de.upb.crypto.math.structures.polynomial.Seed;
import de.upb.crypto.math.structures.quotient.F2FiniteFieldExtension;
import de.upb.crypto.math.structures.quotient.F2FiniteFieldExtension.F2FiniteFieldElement;
import de.upb.crypto.math.structures.quotient.FiniteFieldExtension.FiniteFieldElement;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;

/**
 * Implementation of an \epsilon -biased distribution using polynomials in the
 * galois field. These distributions can be used to specify k-wise \delta
 * -dependent families of hash functions.
 * <p>
 * <p>
 * <p>
 * Construction 3 in: Alon et al., 2002, Simple Constructions of Almost k-wise
 * Independent Random Variables
 * (http://www.math.tau.ac.il/~nogaa/PDFS/aghp4.pdf)
 *
 * @author Mirko Jürgens
 */
public class EpsilonDistribution implements StandaloneRepresentable {

    /**
     * n in the paper
     */
    private int sampleLength;

    /**
     * epsilon in the paper
     */
    private double epsilon;

    private double m;

    /**
     * GF(2^m)
     */
    private F2FiniteFieldExtension baseField;

    /**
     * Specified by the seed!
     */
    private F2FiniteFieldElement x;
    /**
     * Specified by the seed!
     */
    private F2FiniteFieldElement y;

    /**
     * @param sampleLength
     * @param logEpsilon
     * @param seed
     */
    public EpsilonDistribution(int sampleLength, double logEpsilon, Seed seed) {

        this.sampleLength = sampleLength;
        this.epsilon = Math.pow(2, logEpsilon);

        // By definition, this construction yields epsilon:= (n-1)*2^-m biased
        // distributions
        // 2^logEpsilon := (n-1) * 2^-m
        // logEPsilon = log((n-1) * 2^-m)
        // logEPsilon = log (n-1) - m
        // log (n-1) - logEPsilon = m
        

        m = (Math.log((sampleLength - 1)) / Math.log(2)) - logEpsilon;

        Zp ring = new Zp(BigInteger.valueOf(2));

        PolynomialRing polyRing = new PolynomialRing(ring);

        Polynomial random = IrreducibleSupplier.getIrreducible((int) m);

        baseField = new F2FiniteFieldExtension(random);

        int seedLength = (int) (2 * m);
        if (seed.getBitLength() != seedLength) {
            throw new IllegalArgumentException("Invalid Seed length: got " + seed.getBitLength()
                    + " bits, but expected  " + seedLength + " bits!");
        }

        x = baseField.new F2FiniteFieldElement((polyRing.new Polynomial(new Seed(seed.getInternalSeed(), (int) m))));

        y = baseField.new F2FiniteFieldElement(
                polyRing.new Polynomial(new Seed(seed.getInternalSeed(), (int) m, (int) m)));
    }

    public EpsilonDistribution(Representation repr) {
        ObjectRepresentation obj = (ObjectRepresentation) repr;
        epsilon = new Double(obj.get("epsilon").str().get());
        m = new Double(obj.get("m").str().get());
        sampleLength = obj.get("sampleLength").bigInt().getInt();
        baseField = (F2FiniteFieldExtension) obj.get("baseField").repr().recreateRepresentable();
        x = baseField.getElement(obj.get("x"));
        y = baseField.getElement(obj.get("y"));
    }

    public byte[] calculateSample(BigInteger start, int length) {
        F2FiniteFieldElement temp = baseField.new F2FiniteFieldElement((FiniteFieldElement) x.pow(start));
        ZpElement scalar = temp.getRepresentative().scalarProduct(y.getRepresentative());
        
        String output = "" + scalar.getInteger().intValue();

        for (int i = 1; i < length; i++) {
            temp = temp.mul(x);
            scalar = temp.getRepresentative().scalarProduct(y.getRepresentative());
            output = output + "" + scalar.getInteger().intValue();
        }

        BigInteger res = new BigInteger(output, 2);
        return res.toByteArray();
    }

    public BigInteger calculateIthBit(BigInteger i) {
        F2FiniteFieldElement temp = baseField.new F2FiniteFieldElement((FiniteFieldElement) x.pow(i));
        ZpElement scalar = temp.getRepresentative().scalarProduct(y.getRepresentative());
        return scalar.getInteger();
    }

    public int getSampleLength() {
        return sampleLength;
    }

    public double getEpsilon() {
        return epsilon;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation obj = new ObjectRepresentation();
        obj.put("epsilon", new StringRepresentation(Double.toString(epsilon)));
        obj.put("m", new StringRepresentation(Double.toString(m)));
        obj.put("sampleLength", new BigIntegerRepresentation(sampleLength));
        obj.put("x", x.getRepresentation());
        obj.put("y", y.getRepresentation());
        obj.put("baseField", new RepresentableRepresentation(baseField));
        return obj;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((baseField == null) ? 0 : baseField.hashCode());
        long temp;
        temp = Double.doubleToLongBits(epsilon);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        temp = Double.doubleToLongBits(m);
        result = prime * result + (int) (temp ^ (temp >>> 32));
        result = prime * result + sampleLength;
        result = prime * result + ((x == null) ? 0 : x.hashCode());
        result = prime * result + ((y == null) ? 0 : y.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        ;
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        EpsilonDistribution other = (EpsilonDistribution) obj;
        if (baseField == null) {
            if (other.baseField != null)
                return false;
        } else if (!baseField.equals(other.baseField))
            return false;
        if (Double.doubleToLongBits(epsilon) != Double.doubleToLongBits(other.epsilon)) {
            return false;
        }
        if (Double.doubleToLongBits(m) != Double.doubleToLongBits(other.m))
            return false;
        if (sampleLength != other.sampleLength)
            return false;
        if (x == null) {
            if (other.x != null)
                return false;
        } else if (!x.equals(other.x)) {
            return false;
        }
        if (y == null) {
            if (other.y != null)
                return false;
        } else if (!y.equals(other.y))
            return false;
        return true;
    }
}
