package de.upb.crypto.craco.kdf.lhl;

import de.upb.crypto.craco.kdf.interfaces.HashFamily;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.polynomial.Seed;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * The basic approach of a 2-universal hash family. This family is defined as
 * H := \{ h_{a,b} : a \in [p-1] \setminus \{0\}, b \in [p-1] \}.
 * And h_{a,b}(x) := [(ax+b) mod p] mod n
 * where n is the output length and p is a prime \in [n, 2n].
 * <p>
 * Theorem 2 of:
 * https://courses.cs.washington.edu/courses/cse525/13sp/scribe/lec5.pdf
 *
 * @author Mirko Jürgens
 */
public class UniversalHashFamily implements HashFamily {

    // n
    @Represented
    protected Integer inputLength;

    // m
    @Represented
    protected Integer outputLength;

    @Represented
    protected BigInteger p;

    @Represented
    protected BigInteger m;


    public UniversalHashFamily(int inputLength, int outputLength) {
        this.inputLength = inputLength;
        this.outputLength = outputLength;


        m = BigInteger.valueOf(2).pow(outputLength);

        BigInteger n = BigInteger.valueOf(2).pow(inputLength);

        BigInteger two_n = BigInteger.valueOf(2).pow(inputLength + 1);

        SecureRandom rng = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(inputLength + 1, rng);

        while (p.compareTo(two_n) >= 1 || p.compareTo(n) <= -1) {
            p = BigInteger.probablePrime(inputLength + 1, rng);
        }
        this.p = p;
    }

    public UniversalHashFamily(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int getInputLength() {
        return inputLength;
    }

    @Override
    public int getOutputLength() {
        return outputLength;
    }

    @Override
    public int seedLength() {
        return 2 * p.bitLength();
    }

    @Override
    public UniversalHashFunction seedFunction(Seed seed) {
        StringBuilder a = new StringBuilder();
        for (int i = 0; i < p.bitLength(); i++) {
            if (seed.getBitAt(i) == 0)
                a.append(0);
            else
                a.append(1);
        }
        StringBuilder b = new StringBuilder();
        for (int i = p.bitLength(); i < p.bitLength() * 2; i++) {
            if (seed.getBitAt(i) == 0)
                b.append(0);
            else
                b.append(1);
        }
        BigInteger bigA = new BigInteger(a.toString(), 2);
        BigInteger bigB = new BigInteger(b.toString(), 2);

        bigA = bigA.mod(p);
        bigB = bigB.mod(p);
        return new UniversalHashFunction(this, bigA, bigB);
    }

    @Override
    public UniversalHashFunction getHashFunction(Representation repr) {
        return new UniversalHashFunction(repr);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + inputLength;
        result = prime * result + ((m == null) ? 0 : m.hashCode());
        result = prime * result + outputLength;
        result = prime * result + ((p == null) ? 0 : p.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        UniversalHashFamily other = (UniversalHashFamily) obj;
        return Objects.equals(inputLength, other.inputLength)
                && Objects.equals(m, other.m)
                && Objects.equals(outputLength, other.outputLength)
                && Objects.equals(p, other.p);
    }
}
