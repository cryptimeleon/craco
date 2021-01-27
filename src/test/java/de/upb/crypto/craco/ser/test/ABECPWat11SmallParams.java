package de.upb.crypto.craco.ser.test;

import de.upb.crypto.craco.abe.cp.small.*;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.common.policy.Policy;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;

import java.util.HashSet;
import java.util.Set;

public class ABECPWat11SmallParams {
    public static RepresentationTestParams getParams() {

        Set<StringAttribute> universe = new HashSet<>();
        universe.add(new StringAttribute("A"));
        universe.add(new StringAttribute("B"));
        universe.add(new StringAttribute("C"));
        universe.add(new StringAttribute("D"));
        universe.add(new StringAttribute("E"));

        ABECPWat11SmallSetup setup = new ABECPWat11SmallSetup();
        setup.doKeyGen(80, universe, true);

        ABECPWat11SmallPublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11SmallMasterSecret msk = setup.getMasterSecret();
        ABECPWat11Small smallScheme = new ABECPWat11Small(publicParams);

        ThresholdPolicy leftNode = new ThresholdPolicy(1, new StringAttribute("A"), new StringAttribute("B"));
        ThresholdPolicy rightNode =
                new ThresholdPolicy(2, new StringAttribute("C"), new StringAttribute("D"), new StringAttribute("E"));
        Policy policy = new ThresholdPolicy(2, leftNode, rightNode);
        EncryptionKey validPK = smallScheme.generateEncryptionKey(policy);

        SetOfAttributes validAttributes = new SetOfAttributes();
        validAttributes.add(new StringAttribute("A"));
        validAttributes.add(new StringAttribute("D"));
        validAttributes.add(new StringAttribute("E"));

        DecryptionKey validSK = smallScheme.generateDecryptionKey(msk, validAttributes);

        PlainText plaintext = new GroupElementPlainText(publicParams.getGroupGT().getUniformlyRandomElement());

        CipherText ciphertext = (ABECPWat11SmallCipherText) smallScheme.encrypt(plaintext, validPK);

        return new RepresentationTestParams(smallScheme, validPK, validSK, plaintext, ciphertext, msk);
    }

}
