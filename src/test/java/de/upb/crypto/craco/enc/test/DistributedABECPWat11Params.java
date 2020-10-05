package de.upb.crypto.craco.enc.test;

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
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

public class DistributedABECPWat11Params {

    public static ArrayList<TestParams> getParams() {
        Attribute[] stringAttributes = {new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")};
        TestParams stringAttrParams = createGenericParams(stringAttributes);
        Attribute[] integerAttribute =
                {new BigIntegerAttribute(0), new BigIntegerAttribute(1), new BigIntegerAttribute(2),
                        new BigIntegerAttribute(3), new BigIntegerAttribute(4)};
        TestParams integerAttrParams = createGenericParams(integerAttribute);

        ArrayList<TestParams> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        return toReturn;
    }


    static int SERVER_COUNT = 5;
    static int SHARES_NEEDED = 3;

    static int MAX_NUMBER_ATTR = 10;
    static int SECURITY_PARAMETER = 80;

    static int MAX_MSP_COUNT = 10;

    public static TestParams createGenericParams(Attribute[] attributes) {

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
//		DecryptionKey validSK = scheme.combineKeyShares(validKeyShares);
        DecryptionKey invalidSK = scheme.combineKeyShares(invalidKeyShares);

        KeyPair validKeyPair = new KeyPair(pk, validSK);
        KeyPair invalidKeyPair = new KeyPair(pk, invalidSK);

        Supplier<PlainText> supplier = () -> ((PlainText) new GroupElementPlainText(
                pp.getGroupGT().getUniformlyRandomElement()));

        return new TestParams(scheme, supplier, validKeyPair, invalidKeyPair);
    }

}
