package de.upb.crypto.craco.enc.params;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11MasterSecret;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11PublicParameters;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.abe.util.ABECPWat11TestParamGenerator;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.enc.EncryptionSchemeTestParam;

import java.util.ArrayList;
import java.util.List;

public class ABECPWat11Params implements TestParameterProvider {

    public Object get() {
        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecurityParameter, 5 = n = AttributeCount, l_max = 5 (max number of attributes in the MSP)
        setup.doKeyGen(80, 5, 5, false, true);

        ABECPWat11PublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11MasterSecret msk = setup.getMasterSecret();

        ABECPWat11 scheme = new ABECPWat11(publicParams);
        PlainText plainText = new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()
        );

        // string attributes parameters
        List<KeyPair> stringAttrKeys = ABECPWat11TestParamGenerator.generateLargeUniverseTestKeys(msk,
                scheme, ABECPWat11TestParamGenerator.generateStringAttributesToTest());
        EncryptionSchemeTestParam stringAttrParams = new EncryptionSchemeTestParam(
                scheme, plainText, stringAttrKeys.get(0), stringAttrKeys.get(1)
        );

        // integer attributes parameters
        List<KeyPair> integerAttrKeys = ABECPWat11TestParamGenerator.generateLargeUniverseTestKeys(msk,
                scheme, ABECPWat11TestParamGenerator.generateIntegerAttributesToTest());
       EncryptionSchemeTestParam integerAttrParams = new EncryptionSchemeTestParam(
                scheme, plainText, integerAttrKeys.get(0), integerAttrKeys.get(1)
        );

        ArrayList<EncryptionSchemeTestParam> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        return toReturn;
    }
}
