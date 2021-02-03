package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

public class HashBasedKDFParams {

    public static StandaloneTestParams get() {
        // SHA-256-based KDF
        HashBasedKeyDerivationFunction shaBasedKDF = new HashBasedKeyDerivationFunction();
        return new StandaloneTestParams(shaBasedKDF.getClass(), shaBasedKDF);
    }
}
