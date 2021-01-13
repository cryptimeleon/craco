package de.upb.crypto.craco.enc.params;

import de.upb.crypto.craco.abe.cp.small.asymmetric.ABECPWat11AsymSmall;
import de.upb.crypto.craco.abe.cp.small.asymmetric.ABECPWat11AsymSmallMasterSecret;
import de.upb.crypto.craco.abe.cp.small.asymmetric.ABECPWat11AsymSmallPublicParameters;
import de.upb.crypto.craco.abe.cp.small.asymmetric.ABECPWat11AsymSmallSetup;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.policy.BooleanPolicy;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.enc.EncryptionSchemeTestParam;

import java.util.ArrayList;
import java.util.Arrays;

public class ABECPWat11AsymSmallParams implements TestParameterProvider {
    public Object get() {
        Attribute[] stringAttributes = {new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")};
        EncryptionSchemeTestParam stringAttrParams = createGenericParams(stringAttributes);
        Attribute[] integerAttribute =
                {new BigIntegerAttribute(0), new BigIntegerAttribute(1), new BigIntegerAttribute(2),
                        new BigIntegerAttribute(3), new BigIntegerAttribute(4)};
        EncryptionSchemeTestParam integerAttrParams = createGenericParams(integerAttribute);

        ArrayList<EncryptionSchemeTestParam> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        return toReturn;
    }

    private static EncryptionSchemeTestParam createGenericParams(Attribute[] attributes) {

        ABECPWat11AsymSmallSetup setup = new ABECPWat11AsymSmallSetup();

        setup.doKeyGen(80, Arrays.asList(attributes), true);

        ABECPWat11AsymSmallPublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11AsymSmallMasterSecret msk = setup.getMasterSecret();
        ABECPWat11AsymSmall smallScheme = new ABECPWat11AsymSmall(publicParams);

        BooleanPolicy bleftNode = new BooleanPolicy(BooleanPolicy.BooleanOperator.OR, attributes[0], attributes[1]);

        BooleanPolicy bright2 = new BooleanPolicy(BooleanPolicy.BooleanOperator.AND, attributes[3], attributes[4]);

        Policy bPolicy = new BooleanPolicy(BooleanPolicy.BooleanOperator.AND, bleftNode, bright2);

        EncryptionKey validPK = smallScheme.generateEncryptionKey(bPolicy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(attributes[0]);
        validAttributes.add(attributes[3]);
        validAttributes.add(attributes[4]);

        SetOfAttributes invalidAttributes = new SetOfAttributes();
        invalidAttributes.add(attributes[0]);
        invalidAttributes.add(attributes[3]);

        DecryptionKey validSK = smallScheme.generateDecryptionKey(msk, validAttributes);
        DecryptionKey invalidSK = smallScheme.generateDecryptionKey(msk, invalidAttributes);

        KeyPair validKeyPair = new KeyPair(validPK, validSK);
        KeyPair invalidKeyPair = new KeyPair(validPK, invalidSK);

        PlainText plainText = new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()
        );

        return new EncryptionSchemeTestParam(smallScheme, plainText, validKeyPair, invalidKeyPair);
    }
}
