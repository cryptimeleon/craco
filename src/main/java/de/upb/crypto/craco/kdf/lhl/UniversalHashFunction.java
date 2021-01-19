package de.upb.crypto.craco.kdf.lhl;

import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Objects;

/**
 * An instance of a {@link UniversalHashFamily}.
 *
 * @see UniversalHashFamily
 *
 *
 */
public class UniversalHashFunction implements HashFunction {

    @Represented
    private UniversalHashFamily universalHashFamily;

    @Represented
    private BigInteger a;

    @Represented
    private BigInteger b;

    public UniversalHashFunction(UniversalHashFamily universalHashFamily, BigInteger a, BigInteger b) {
        this.universalHashFamily = universalHashFamily;
        this.a = a;
        this.b = b;
    }

    public UniversalHashFunction(Representation repr) {
        new ReprUtil(this).deserialize(repr);

    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        UniversalHashFunction that = (UniversalHashFunction) o;

        return Objects.equals(universalHashFamily, that.universalHashFamily)
            && Objects.equals(a, that.a)
            && Objects.equals(b, that.b);
    }

    @Override
    public int hashCode() {
        int result = universalHashFamily != null ? universalHashFamily.hashCode() : 0;
        result = 31 * result + (a != null ? a.hashCode() : 0);
        result = 31 * result + (b != null ? b.hashCode() : 0);
        return result;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int getOutputLength() {
        return universalHashFamily.getOutputLength();
    }

    @Override
    public byte[] hash(byte[] bytes) {
        BigInteger x = new BigInteger(bytes);
        BigInteger h = a.multiply(x).add(b).mod(universalHashFamily.p).mod(universalHashFamily.m);
        byte[] b = h.toByteArray();
        byte[] toReturn = new byte[universalHashFamily.outputLength / 8];
        // 29.10 mirkoj: java somehow manages to let an extra empty byte be in the front if all bytes of the
        // h.toByteArray() function are filled (e.g. h is exactly a power of 2^8)
        if (h.bitLength() == universalHashFamily.outputLength && b.length != universalHashFamily.outputLength / 8
                && b[0] == 0) {
            System.arraycopy(h.toByteArray(), 1, toReturn, 0, universalHashFamily.outputLength / 8);
        } else {
            toReturn = b;
        }
        return toReturn;
    }

}
