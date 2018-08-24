package de.upb.crypto.craco.kdf.uextr;

import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.polynomial.Seed;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * A seeded {@link HashFunction} of a {@link KWiseDeltaDependentHashFamily}.
 * This {@link HashFunction} uses an {@link EpsilonDistribution} to generate
 * its hash values.
 * <p>
 * Such a function can be seeded with
 * {@link KWiseDeltaDependentHashFamily#seedFunction(Seed)}.
 *
 * @author Mirko Jürgens, refactoring: Denis Diemert
 */
public class KWiseDeltaDependentHashFunction implements HashFunction {

    private static final Logger logger = LogManager.getLogger("KWiseDeltaDependentHashFamilyLogger");

    @Represented
    private KWiseDeltaDependentHashFamily kWiseDeltaDependentHashFamily;
    @Represented
    private EpsilonDistribution underlyingDistribution;

    public KWiseDeltaDependentHashFunction(KWiseDeltaDependentHashFamily kWiseDeltaDependentHashFamily, Seed seed) {
        this.kWiseDeltaDependentHashFamily = kWiseDeltaDependentHashFamily;
        setupEpsilonDistribution(kWiseDeltaDependentHashFamily.getK(), kWiseDeltaDependentHashFamily.getDelta(), seed);
    }

    private void setupEpsilonDistribution(double k, double logDelta, Seed seed) {
        int sampleLength =
                kWiseDeltaDependentHashFamily.getInputLength() * kWiseDeltaDependentHashFamily.getOutputLength();

        // double temp = Math.pow(2, (-k * outputLength * 0.5));
        double logTemp = -k * kWiseDeltaDependentHashFamily.getOutputLength() * 0.5;

        double logEpsilon = logDelta + logTemp;

        logger.debug("Setting up internal epsilon distribution with logEpsilon: " + logEpsilon + " sampleLength: "
                + sampleLength + " seed: " + Arrays.toString(seed.getInternalSeed()));

        underlyingDistribution = new EpsilonDistribution(sampleLength, logEpsilon, seed);
    }

    public KWiseDeltaDependentHashFunction(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public int getOutputLength() {
        return kWiseDeltaDependentHashFamily.getOutputLength();
    }

    @Override
    public byte[] hash(UniqueByteRepresentable ubr) {
        ByteAccumulator acc = new ByteArrayAccumulator();
        acc = ubr.updateAccumulator(acc);
        byte[] bytes = acc.extractBytes();
        return hash(bytes);
    }

    @Override
    public byte[] hash(byte[] bytes) {
        if (!validateInputLength(bytes))
            throw new IllegalArgumentException("Invalid input length:  expected " + kWiseDeltaDependentHashFamily
                    .getInputLength() + " bits!");
        // count the element number
        logger.info("Hashing: " + Arrays.toString(bytes));
        BigInteger unsigned = BigIntegerUtil.getUnsingendBigInteger(bytes);
        logger.info("Requesting the:" + unsigned + "th sample from the underlying distribution.");
        BigInteger start = unsigned.multiply(BigInteger.valueOf(kWiseDeltaDependentHashFamily.getInputLength()));
        return underlyingDistribution.calculateSample(start, kWiseDeltaDependentHashFamily.getOutputLength());
    }

    private boolean validateInputLength(byte[] bytes) {
        int bitLength = bytes.length * 8;
        if (bitLength == kWiseDeltaDependentHashFamily.getInputLength()) {
            return true;
        }
        if (bitLength < kWiseDeltaDependentHashFamily.getInputLength()) {
            return false;
        }
        // case inputLength is not a multiplicate of 8, then the last byte[]
        // should have leading zeroes
        if (kWiseDeltaDependentHashFamily.getInputLength() % 8 == 0) {
            return false;
        }
        int bits = kWiseDeltaDependentHashFamily.getInputLength() % 8;
        int nonZeroBits = 8 - bits;
        // the last byte should be smaller than 2^nonZeroBits
        return bytes[bytes.length - 1] <= Math.pow(2, nonZeroBits);

    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + getOuterType().hashCode();
        result = prime * result + ((underlyingDistribution == null) ? 0 : underlyingDistribution.hashCode());
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
        KWiseDeltaDependentHashFunction other = (KWiseDeltaDependentHashFunction) obj;
        if (!getOuterType().equals(other.getOuterType()))
            return false;
        if (underlyingDistribution == null) {
            if (other.underlyingDistribution != null)
                return false;
        } else if (!underlyingDistribution.equals(other.underlyingDistribution))
            return false;
        return true;
    }

    private KWiseDeltaDependentHashFamily getOuterType() {
        return kWiseDeltaDependentHashFamily;
    }
}
