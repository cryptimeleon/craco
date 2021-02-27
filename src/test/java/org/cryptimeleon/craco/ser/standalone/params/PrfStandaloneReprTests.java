package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.prf.aes.AesPseudorandomFunction;
import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;

public class PrfStandaloneReprTests extends StandaloneReprSubTest {
    public void testAes() {
        test(new AesPseudorandomFunction(128));
    }
}
