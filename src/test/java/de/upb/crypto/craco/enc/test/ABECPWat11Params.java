package de.upb.crypto.craco.enc.test;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11MasterSecret;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11PublicParameters;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.abe.util.ABECPWat11TestParamGenerator;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.interfaces.KeyPair;
import de.upb.crypto.craco.interfaces.PlainText;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

public class ABECPWat11Params {
    public static ArrayList<TestParams> getParams() {
        ABECPWat11Setup setup = new ABECPWat11Setup();

        // 80=SecrurityParameter, 5 = n = AttributeCount, l_max = 5 (max number of attributes in the MSP)
        setup.doKeyGen(80, 5, 5, false, true);

        ABECPWat11PublicParameters publicParams = setup.getPublicParameters();
        ABECPWat11MasterSecret msk = setup.getMasterSecret();

        ABECPWat11 scheme = new ABECPWat11(publicParams);
        Supplier<PlainText> supplier = () -> ((PlainText) new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()));

        // string attributes parameters
        List<KeyPair> stringAttrKeys = ABECPWat11TestParamGenerator.generateLargeUniverseTestKeys(msk,
                scheme, ABECPWat11TestParamGenerator.generateStringAttributesToTest());
        TestParams stringAttrParams = new TestParams(scheme, supplier, stringAttrKeys.get(0), stringAttrKeys.get(1));

        // integer attributes parameters
        List<KeyPair> integerAttrKeys = ABECPWat11TestParamGenerator.generateLargeUniverseTestKeys(msk,
                scheme, ABECPWat11TestParamGenerator.generateIntegerAttributesToTest());
        TestParams integerAttrParams = new TestParams(scheme, supplier, integerAttrKeys.get(0), integerAttrKeys.get(1));

        ArrayList<TestParams> toReturn = new ArrayList<>();
        toReturn.add(stringAttrParams);
        toReturn.add(integerAttrParams);
        return toReturn;
    }
}
