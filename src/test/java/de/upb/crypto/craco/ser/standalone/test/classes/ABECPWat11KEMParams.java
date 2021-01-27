package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.predenc.kem.abe.cp.large.ABECPWat11KEM;

public class ABECPWat11KEMParams {

    public static StandaloneTestParams get() {
        ABECPWat11Setup setup = new ABECPWat11Setup();
        setup.doKeyGen(80, 5, 5, false, true);
        return new StandaloneTestParams(ABECPWat11KEM.class,
                new ABECPWat11KEM(setup.getPublicParameters()));
    }

}
