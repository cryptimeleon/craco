package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.craco.sig.bbs.BBSBKeyGen;
import de.upb.crypto.craco.sig.bbs.BBSBPublicParameter;
import de.upb.crypto.craco.sig.bbs.BBSBSignatureScheme;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class BBSBParams {

    public static Collection<StandaloneTestParams> get() {
        BBSBKeyGen setup = new BBSBKeyGen();
        BBSBPublicParameter pp = setup.doKeyGen(80, true);
        List<StandaloneTestParams> toReturn = new ArrayList<>();
        toReturn.add(new StandaloneTestParams(BBSBPublicParameter.class, pp));
        toReturn.add(new StandaloneTestParams(BBSBSignatureScheme.class,
                new BBSBSignatureScheme(pp)));
        return toReturn;
    }
}
