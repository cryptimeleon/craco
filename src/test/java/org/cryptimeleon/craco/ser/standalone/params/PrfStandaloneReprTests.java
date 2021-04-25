package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.prf.aes.AesPseudorandomFunction;
import org.cryptimeleon.craco.prf.zn.HashThenPrfToZn;
import org.cryptimeleon.craco.prf.zn.LongAesPseudoRandomFunction;
import org.cryptimeleon.math.hash.impl.SHA256HashFunction;
import org.cryptimeleon.math.serialization.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.structures.rings.zn.Zn;

import java.math.BigInteger;
import java.util.Random;

public class PrfStandaloneReprTests extends StandaloneReprSubTest {
    public void testAes() {
        test(new AesPseudorandomFunction(128));
    }

    public void testLongAes() {
        test(new LongAesPseudoRandomFunction(new AesPseudorandomFunction(128), 9));
    }

    public void testAesToZn() {
        BigInteger p = BigInteger.probablePrime(400, new Random());
        Zn zn = new Zn(p);
        test(new HashThenPrfToZn(128, zn, new SHA256HashFunction(), 64));
    }
}
