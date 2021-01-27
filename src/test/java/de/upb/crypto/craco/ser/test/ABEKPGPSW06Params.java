package de.upb.crypto.craco.ser.test;

import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.abe.kp.large.*;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.common.policy.Policy;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;

public class ABEKPGPSW06Params {
    public static RepresentationTestParams getParams() {

        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 10, false, true);

        ABEKPGPSW06MasterSecret msk = setup.getMasterSecret();
        ABEKPGPSW06PublicParameters publicParams = setup.getPublicParameters();

        ABEKPGPSW06 scheme = new ABEKPGPSW06(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));

        ThresholdPolicy rightNode =
                new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));

        Policy validPolicy = new ThresholdPolicy(2, leftNode, rightNode);
        DecryptionKey validSK = (ABEKPGPSW06DecryptionKey) scheme.generateDecryptionKey(msk, validPolicy);

        SetOfAttributes validPublicAttributes = new SetOfAttributes();
        validPublicAttributes.add(new StringAttribute("A"));
        validPublicAttributes.add(new StringAttribute("D"));
        validPublicAttributes.add(new StringAttribute("E"));

        EncryptionKey validPK = (ABEKPGPSW06EncryptionKey) scheme.generateEncryptionKey(validPublicAttributes);

        PlainText plaintext = new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement());

        CipherText ciphertext = (ABEKPGPSW06CipherText) scheme.encrypt(plaintext, validPK);

        return new RepresentationTestParams(scheme, validPK, validSK, plaintext, ciphertext, msk);
    }
}