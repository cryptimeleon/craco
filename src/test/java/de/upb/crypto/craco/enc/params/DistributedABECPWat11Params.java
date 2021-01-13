package de.upb.crypto.craco.enc.params;

import de.upb.crypto.craco.abe.cp.large.distributed.DistributedABECPWat11;
import de.upb.crypto.craco.abe.cp.large.distributed.DistributedABECPWat11MasterKeyShare;
import de.upb.crypto.craco.abe.cp.large.distributed.DistributedABECPWat11PublicParameters;
import de.upb.crypto.craco.abe.cp.large.distributed.DistributedABECPWat11Setup;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.abe.interfaces.distributed.KeyShare;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.enc.EncryptionSchemeTestParam;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class DistributedABECPWat11Params implements TestParameterProvider {

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

    static int SERVER_COUNT = 5;
    static int SHARES_NEEDED = 3;

    static int MAX_NUMBER_ATTR = 10;
    static int SECURITY_PARAMETER = 80;

    static int MAX_MSP_COUNT = 10;

    public static EncryptionSchemeTestParam createGenericParams(Attribute[] attributes) {

        DistributedABECPWat11Setup setup = new DistributedABECPWat11Setup();
        setup.doKeyGen(SECURITY_PARAMETER, MAX_NUMBER_ATTR, MAX_MSP_COUNT, SHARES_NEEDED, SERVER_COUNT, true);

        DistributedABECPWat11PublicParameters pp = setup.getPublicParameters();
        Set<DistributedABECPWat11MasterKeyShare> mskShares = setup.getMasterKeyShares();

        DistributedABECPWat11 scheme = new DistributedABECPWat11(pp);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);

        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);

        Policy policy = new ThresholdPolicy(2, leftNode, rightNode);

        EncryptionKey pk = scheme.generateEncryptionKey((CiphertextIndex) policy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(attributes[0]);
        validAttributes.add(attributes[3]);
        validAttributes.add(attributes[4]);

        List<KeyShare> validKeyShares = new ArrayList<>();

        Iterator<DistributedABECPWat11MasterKeyShare> shareIterator = mskShares.iterator();
        for (int i = 0; i < SHARES_NEEDED; i++) {
            DistributedABECPWat11MasterKeyShare share = shareIterator.next();
            validKeyShares.add(scheme.generateKeyShare(share, validAttributes));
        }

        SetOfAttributes invalidAttributes = new SetOfAttributes();
        invalidAttributes.add(attributes[0]);
        invalidAttributes.add(attributes[3]);

        List<KeyShare> invalidKeyShares = new ArrayList<>();

        shareIterator = mskShares.iterator();
        for (int i = 0; i < SHARES_NEEDED; i++) {
            DistributedABECPWat11MasterKeyShare share = shareIterator.next();
            invalidKeyShares.add(scheme.generateKeyShare(share, invalidAttributes));
        }

        DecryptionKey validSK = scheme.generateDecryptionKey(setup.getMasterSecret(), validAttributes);
        DecryptionKey invalidSK = scheme.combineKeyShares(invalidKeyShares);

        KeyPair validKeyPair = new KeyPair(pk, validSK);
        KeyPair invalidKeyPair = new KeyPair(pk, invalidSK);

        PlainText plainText = new GroupElementPlainText(
                pp.getGroupGT().getUniformlyRandomElement()
        );

        return new EncryptionSchemeTestParam(scheme, plainText, validKeyPair, invalidKeyPair);
    }
}
