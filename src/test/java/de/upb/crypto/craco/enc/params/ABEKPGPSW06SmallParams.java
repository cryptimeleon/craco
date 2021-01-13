package de.upb.crypto.craco.enc.params;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.abe.kp.small.ABEKPGPSW06Small;
import de.upb.crypto.craco.abe.kp.small.ABEKPGPSW06SmallMasterSecret;
import de.upb.crypto.craco.abe.kp.small.ABEKPGPSW06SmallPublicParameters;
import de.upb.crypto.craco.abe.kp.small.ABEKPGPSW06SmallSetup;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.enc.EncryptionSchemeTestParam;

import java.util.ArrayList;
import java.util.Arrays;

public class ABEKPGPSW06SmallParams implements TestParameterProvider {

    @Override
    public Object get() {
        Attribute[] stringAttributes = {
                new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")
        };
        EncryptionSchemeTestParam stringAttrParams = createGenericParams(stringAttributes);
        Attribute[] integerAttribute = {
                new BigIntegerAttribute(0), new BigIntegerAttribute(1),
                new BigIntegerAttribute(2), new BigIntegerAttribute(3),
                new BigIntegerAttribute(4)
        };
        EncryptionSchemeTestParam integerAttrParams = createGenericParams(integerAttribute);

        ArrayList<EncryptionSchemeTestParam> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        return toReturn;
    }

    private static EncryptionSchemeTestParam createGenericParams(Attribute[] attributes) {

        ABEKPGPSW06SmallSetup setup = new ABEKPGPSW06SmallSetup();
        setup.doKeyGen(80, Arrays.asList(attributes), true);

        ABEKPGPSW06SmallMasterSecret msk = setup.getMasterSecret();
        ABEKPGPSW06SmallPublicParameters publicParams = setup.getPublicParameters();

        ABEKPGPSW06Small scheme = new ABEKPGPSW06Small(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);
        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);
        Policy validPolicy = new ThresholdPolicy(2, leftNode, rightNode);

        ThresholdPolicy invalidLeftNode = new ThresholdPolicy(2, attributes[0], attributes[1]);
        ThresholdPolicy invalidRightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);
        Policy invalidPolicy = new ThresholdPolicy(2, invalidLeftNode, invalidRightNode);

        DecryptionKey validSK = scheme.generateDecryptionKey(msk, validPolicy);
        DecryptionKey invalidSK = scheme.generateDecryptionKey(msk, invalidPolicy);

        SetOfAttributes validPublicAttributes = new SetOfAttributes();
        validPublicAttributes.add(attributes[0]);
        validPublicAttributes.add(attributes[3]);
        validPublicAttributes.add(attributes[4]);

        EncryptionKey validPK = scheme.generateEncryptionKey(validPublicAttributes);

        KeyPair validKeyPair = new KeyPair(validPK, validSK);
        KeyPair invalidKeyPair = new KeyPair(validPK, invalidSK);

        PlainText plainText = new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()
        );
        return new EncryptionSchemeTestParam(scheme, plainText, validKeyPair, invalidKeyPair);
    }
}
