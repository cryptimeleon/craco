package de.upb.crypto.craco.kdf.lhl;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.polynomial.Seed;

import java.math.BigInteger;
import java.util.Objects;

/**
 * A standard implementation of a key derivation function using the Leftover-Hash-Lemma and 2-universal hash functionss.
 * This approach yields secure key derivation functions as long as the source has enough entropy.
 *
 * @author Mirko Jürgens
 */
public class LHLFamily implements StandaloneRepresentable {

    private static final String insufficient_entropy =
            "The given source of randomness has an insufficient amount of entropy for this key derivation process.";

    @Represented
    protected Integer securityParameter, inputLength, outputLength, minEntropy;

    @Represented
    protected UniversalHashFamily family;

    /**
     * Checks whether the given parameters have sufficient entropy and then generates a {@link UniversalHashFamily}
     * for the given parameters.
     * A key derivation function can then be extracted by calling {@link LHLFamily#seed(Seed)}.
     *
     * @param securityParameter the security parameter in number of bits
     * @param inputLength       the input length of the hash function
     * @param outputlength      the output length of the hash function
     * @param minEntropy        the min entropy of the source of randomness
     * @throws InsufficientEntropyException if the given parameters do not have enough entropy for the given key length
     */
    public LHLFamily(int securityParameter, int inputLength, int outputlength, int minEntropy)
            throws InsufficientEntropyException {
        this.securityParameter = securityParameter;
        this.inputLength = inputLength;
        this.outputLength = outputlength;
        this.minEntropy = minEntropy;

        int two_epsilon = 2 * securityParameter;
        BigInteger m = BigInteger.valueOf(outputlength);
        BigInteger threshold = BigInteger.valueOf(((long) minEntropy) - two_epsilon);

        if (m.compareTo(threshold) >= 1) {
            throw new InsufficientEntropyException(insufficient_entropy);
        }
        family = new UniversalHashFamily(inputLength, outputlength);

    }

    public LHLFamily(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public int getSeedLength() {
        return family.seedLength();
    }

    public LHLKeyDerivationFunction seed(Seed seed) {
        return new LHLKeyDerivationFunction(family.seedFunction(seed));
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((family == null) ? 0 : family.hashCode());
        result = prime * result + inputLength;
        result = prime * result + minEntropy;
        result = prime * result + outputLength;
        result = prime * result + securityParameter;
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
        LHLFamily other = (LHLFamily) obj;
        return Objects.equals(family, other.family)
                && Objects.equals(inputLength, other.inputLength)
                && Objects.equals(minEntropy, other.minEntropy)
                && Objects.equals(outputLength, other.outputLength)
                && Objects.equals(securityParameter, other.securityParameter);
    }

    public LHLKeyDerivationFunction seed() {
        return seed(new Seed(getSeedLength()));
    }
}
