package de.upb.crypto.craco.kdf.uextr;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.kdf.HashFamily;
import de.upb.crypto.craco.kem.KeyDerivationFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedList;
import de.upb.crypto.math.structures.polynomial.Seed;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class UnpredictabilityKeyDerivationFamily implements StandaloneRepresentable {

    private static final Logger logger = LogManager.getLogger(UnpredictabilityKeyDerivationFamily.class.getName());

    @RepresentedList(elementRestorer = @Represented)
    private ArrayList<KWiseDeltaDependentHashFamily> familyList;

    /**
     * n in the paper
     */
    @Represented
    private int inputLength;

    /**
     * k in the paper
     */
    @Represented
    private int minEntropy;

    /**
     * @param securityParameter the success probability of an attacker noted in negative log_2, i.e. 80 if the
     *                          success probability is
     *                          2^-80
     * @param sourceLength      the input length of the KDF
     * @param outputLength      the key-length of the derived key, this also implies that the given min-entropy has
     *                          to be at least the
     *                          key-length (as we have no entropy loss)
     */
    public UnpredictabilityKeyDerivationFamily(int securityParameter, int sourceLength, int outputLength) {

        logger.debug("Setting up a UnpredictabilityKeyDerivationFamily with securityParameter: " + securityParameter
                + " sourceLength: " + sourceLength + " outputLength: " + outputLength);
        inputLength = sourceLength;

        this.minEntropy = outputLength;

        // 2^-securityParameter := n * k + 2^-t
        // securityParameter + log (nk) = t
        long nk = inputLength * outputLength;
        double t = Math.log(nk) / Math.log(2) + securityParameter;

        logger.debug("T:" + t);
        familyList = new ArrayList<>();

        double logT = Math.log(t) / Math.log(2);
        logger.debug("LogT:" + logT);
        double logk = Math.log(outputLength) / (Math.log(4) - Math.log(3));
        logger.debug("logK:" + logk);
        double loglogk = Math.log(logk) / Math.log(2);
        logger.debug("loglogK:" + loglogk);
        double upper = logT + loglogk + 7;
        logger.debug("upper:" + upper);

        int liSum = 0;
        int li = (int) upper + 1;
        int i = 0;
        logger.debug("---------------------------");
        while (li >= upper) {
            i++;
            double temp = 1 - (Math.pow(3, i) / Math.pow(4, i));
            logger.debug("temp:" + temp);
            int threshold = (int) Math.floor((1 - (Math.pow(3, i) / Math.pow(4, i))) * outputLength);
            li = threshold - liSum;
            logger.debug("l_i:" + li);
            liSum += li;

            double qi = 4 * Math.ceil(t / li) + 1;
            logger.debug("qi:" + qi);
            double logDelta = -18 * outputLength;
            logger.debug("logDelta:" + logDelta);

            KWiseDeltaDependentHashFamily family = new KWiseDeltaDependentHashFamily(qi, logDelta, inputLength, li);
            familyList.add(family);
            logger.debug("-------------------");
        }
        liSum -= li;
        int lr1 = outputLength - liSum;
        double qr1 = 4 * t + 1;
        double deltar1 = Math.pow(2, -t * lr1 - 2 * t);
        KWiseDeltaDependentHashFamily familyr1 = new KWiseDeltaDependentHashFamily(qr1, deltar1, inputLength, lr1);
        familyList.add(i, familyr1);
    }

    public UnpredictabilityKeyDerivationFamily(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public List<KWiseDeltaDependentHashFamily> getFamilyList() {
        return familyList;
    }

    public int getInputLength() {
        return inputLength;
    }

    public int minEntropy() {
        return minEntropy;
    }

    public int seedLength() {
        int sum = 0;
        for (HashFamily h : familyList) {
            sum += h.seedLength();
        }
        return sum;
    }

    public KeyDerivationFunction<ByteArrayImplementation> seed(Seed seed) {
        return new UnpredictabilityKeyDerivationFunction(this, seed);
    }

    public KeyDerivationFunction<ByteArrayImplementation> seed() {
        return new UnpredictabilityKeyDerivationFunction(this, new Seed(seedLength()));
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((familyList == null) ? 0 : familyList.hashCode());
        result = prime * result + inputLength;
        result = prime * result + minEntropy;
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
        UnpredictabilityKeyDerivationFamily other = (UnpredictabilityKeyDerivationFamily) obj;
        if (familyList == null) {
            if (other.familyList != null)
                return false;
        } else if (!familyList.equals(other.familyList))
            return false;
        if (inputLength != other.inputLength)
            return false;
        if (minEntropy != other.minEntropy)
            return false;
        return true;
    }

}
