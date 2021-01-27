package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;

public class AesPseudorandomFunction {
    public static StandaloneTestParams get() {
        de.upb.crypto.craco.prf.aes.AesPseudorandomFunction prf =
                new de.upb.crypto.craco.prf.aes.AesPseudorandomFunction(128);
        return new StandaloneTestParams(prf.getClass(), prf);
    }
}
