package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.kem.HashBasedKeyDerivationFunction;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class HashBasedKDFParams {

    public static StandaloneTestParams get() {
        // SHA-256-based KDF
        HashBasedKeyDerivationFunction shaBasedKDF = new HashBasedKeyDerivationFunction();
        return new StandaloneTestParams(shaBasedKDF.getClass(), shaBasedKDF);
    }
}
