package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

public class HashBasedKDFParams {

    public static StandaloneTestParams get() {
        // SHA-256-based KDF
        HashBasedKeyDerivationFunction shaBasedKDF = new HashBasedKeyDerivationFunction();
        return new StandaloneTestParams(shaBasedKDF.getClass(), shaBasedKDF);
    }
}
