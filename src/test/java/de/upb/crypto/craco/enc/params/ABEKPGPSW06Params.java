package de.upb.crypto.craco.enc.params;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06MasterSecret;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06PublicParameters;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06Setup;
import de.upb.crypto.craco.abe.util.ABEKPGPSW06TestParamsGenerator;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.enc.EncryptionSchemeTestParam;

import java.util.ArrayList;
import java.util.List;

public class ABEKPGPSW06Params implements TestParameterProvider {
    @Override
    public Object get() {
        ArrayList<EncryptionSchemeTestParam> toReturn = new ArrayList<>();

        // setup KP environment with security parameter = 80, maximal number of attributes = 10
        ABEKPGPSW06Setup setup = new ABEKPGPSW06Setup();
        setup.doKeyGen(80, 10, false, true);

        ABEKPGPSW06MasterSecret msk = setup.getMasterSecret();
        ABEKPGPSW06PublicParameters publicParams = setup.getPublicParameters();
        ABEKPGPSW06 scheme = new ABEKPGPSW06(publicParams);

        PlainText plainText = new GroupElementPlainText(
                publicParams.getGroupGT().getUniformlyRandomElement()
        );

        // test string attributes, test with 5 attributes
        Attribute[] stringAttr = ABEKPGPSW06TestParamsGenerator.generateStringAttributes();
        List<KeyPair> strKeyPairs = ABEKPGPSW06TestParamsGenerator.generateKeyPairs(scheme, msk, stringAttr);
        toReturn.add(new EncryptionSchemeTestParam(scheme, plainText, strKeyPairs.get(0), strKeyPairs.get(1)));

        // test integer attributes, test with 5 attributes
        Attribute[] intAttr = ABEKPGPSW06TestParamsGenerator.generateIntegerAttributes();
        List<KeyPair> intKeyPairs = ABEKPGPSW06TestParamsGenerator.generateKeyPairs(scheme, msk, intAttr);
        toReturn.add(new EncryptionSchemeTestParam(scheme, plainText, intKeyPairs.get(0), intKeyPairs.get(1)));

        return toReturn;
    }
}
