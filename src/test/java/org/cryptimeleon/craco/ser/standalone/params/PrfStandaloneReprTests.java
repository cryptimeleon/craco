package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.prf.aes.AesPseudorandomFunction;
import org.cryptimeleon.craco.prf.zn.LongAesPseudoRandomFunction;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;

public class PrfStandaloneReprTests extends StandaloneReprSubTest {
    public void testAes() {
        test(new AesPseudorandomFunction(128));
    }

    public void testLongAes() {
        test(new LongAesPseudoRandomFunction(new AesPseudorandomFunction(128), 9));
    }
}
