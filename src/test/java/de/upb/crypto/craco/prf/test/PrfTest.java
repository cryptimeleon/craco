package de.upb.crypto.craco.prf.test;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.prf.PrfImage;
import de.upb.crypto.craco.prf.PrfKey;
import de.upb.crypto.craco.prf.PrfPreimage;
import de.upb.crypto.craco.prf.PseudorandomFunction;
import de.upb.crypto.craco.prf.aes.AesPseudorandomFunction;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;
import java.util.function.Supplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Does generic testing of rings
 */
@RunWith(Parameterized.class)
public class PrfTest {
    private PseudorandomFunction prf;
    private Supplier<PrfPreimage> preimageSupplier;

    public PrfTest(TestParams params) {
        this.prf = params.prf;
        this.preimageSupplier = params.preimageSupplier;
    }

    @Test
    public void testRun() {
        PrfKey k = prf.generateKey();
        assertNotNull(prf.evaluate(k, preimageSupplier.get()));
    }

    @Test
    public void testSerialization() {
        PrfKey k = prf.generateKey();
        assertEquals(k, prf.getKey(k.getRepresentation()));

        PrfPreimage x = preimageSupplier.get();
        assertEquals(x, prf.getPreimage(x.getRepresentation()));

        PrfImage y = prf.evaluate(k, x);
        assertEquals(y, prf.getImage(y.getRepresentation()));
    }

    @Parameters(name = "Test: {0}") // add (name="Test: {0}") for jUnit 4.12+ to print ring's name to test
    public static Collection<TestParams[]> data() {
        // AES
        AesPseudorandomFunction aes = new AesPseudorandomFunction(128);

        // Collect parameters
        TestParams params[][] = new TestParams[][]{
                {new TestParams(aes, () -> ByteArrayImplementation.fromRandom(128 / 8))}
        };
        return Arrays.asList(params);
    }

    private static class TestParams {
        private PseudorandomFunction prf;
        private Supplier<PrfPreimage> preimageSupplier;

        public TestParams(PseudorandomFunction prf, Supplier<PrfPreimage> preimageSupplier) {
            this.prf = prf;
            this.preimageSupplier = preimageSupplier;
        }

        @Override
        public String toString() {
            return prf.getClass().getName() + " - " + prf.toString();
        }
    }
}
