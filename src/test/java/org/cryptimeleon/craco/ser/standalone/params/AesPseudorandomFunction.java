package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;

public class AesPseudorandomFunction {
    public static StandaloneTestParams get() {
        org.cryptimeleon.craco.prf.aes.AesPseudorandomFunction prf =
                new org.cryptimeleon.craco.prf.aes.AesPseudorandomFunction(128);
        return new StandaloneTestParams(prf.getClass(), prf);
    }
}
