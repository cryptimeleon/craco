package de.upb.crypto.craco.abe.util;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11MasterSecret;
import de.upb.crypto.craco.abe.cp.large.AbstractABECPWat11;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.kem.abe.cp.large.ABECPWat11KEM;

import java.util.Arrays;
import java.util.List;

public class ABECPWat11TestParamGenerator {
    /**
     * Returns test keys for the ABE scheme {@link ABECPWat11} and the KEM
     * {@link ABECPWat11KEM}. It internally sets up a public key with a policy based
     * on the given attributes. It requires a fixed amount of attributes, namely five, and implements the policy
     * <p>
     * (a_0 OR a_1) AND (a_2 AND a_3 OR a_2 AND a_4 OR a_3 AND a_4)
     * <p>
     * via a {@link ThresholdPolicy}.
     *
     * @param msk        master secret key for {@code scheme}
     * @param scheme     scheme based on the {@link AbstractABECPWat11}
     * @param attributes attributes to build a policy on size should be 4
     * @return List of two keys: 1. is valid, 2. is invalid
     */
    public static List<KeyPair> generateLargeUniverseTestKeys(ABECPWat11MasterSecret msk,
                                                              AbstractABECPWat11 scheme, Attribute[] attributes) {
        if (attributes.length != 5) {
            throw new IllegalArgumentException("This test only supports attribute sets of size 5.");
        }

        // build up policy
        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);
        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);
        Policy policy = new ThresholdPolicy(2, leftNode, rightNode);

        EncryptionKey pk = scheme.generateEncryptionKey(policy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(attributes[0]);
        validAttributes.add(attributes[3]);
        validAttributes.add(attributes[4]);

        SetOfAttributes invalidAttributes = new SetOfAttributes();
        invalidAttributes.add(attributes[0]);
        invalidAttributes.add(attributes[3]);

        DecryptionKey validSK = scheme.generateDecryptionKey(msk, validAttributes);
        DecryptionKey invalidSK = scheme.generateDecryptionKey(msk, invalidAttributes);

        KeyPair validKeyPair = new KeyPair(pk, validSK);
        KeyPair invalidKeyPair = new KeyPair(pk, invalidSK);

        return Arrays.asList(validKeyPair, invalidKeyPair);
    }

    /**
     * @return Array of five string attributes to be used in combination with
     * <p>
     * <p>
     * <p>
     * <p>
     * <p>
     * <p>
     * <p>
     * <p>
     * {@link ABECPWat11TestParamGenerator#generateLargeUniverseTestKeys(ABECPWat11MasterSecret, AbstractABECPWat11, Attribute[])}
     */
    public static Attribute[] generateStringAttributesToTest() {
        return new StringAttribute[]{new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")};
    }

    /**
     * @return Array of five integer attributes to be used in combination with
     * <p>
     * <p>
     * <p>
     * <p>
     * <p>
     * <p>
     * <p>
     * <p>
     * {@link ABECPWat11TestParamGenerator#generateLargeUniverseTestKeys(ABECPWat11MasterSecret, AbstractABECPWat11, Attribute[])}
     */
    public static Attribute[] generateIntegerAttributesToTest() {
        return new BigIntegerAttribute[]{new BigIntegerAttribute(0), new BigIntegerAttribute(1),
                new BigIntegerAttribute(2), new BigIntegerAttribute(3), new BigIntegerAttribute(4)};
    }
}
