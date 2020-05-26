package de.upb.crypto.craco.sig.ps18;

import com.github.noconnor.junitperf.JUnitPerfRule;
import com.github.noconnor.junitperf.JUnitPerfTest;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

@Ignore
public class PS18SigSchemePerfTest {

    private static PS18SignatureScheme psScheme;
    private static MessageBlock message;
    private static SignatureKeyPair<? extends PS18VerificationKey, ? extends PS18SigningKey>
            keyPair;
    private static PS18Signature sig;

    @Rule
    public JUnitPerfRule perfTestRule = new JUnitPerfRule();

    @BeforeClass
    public static void setUp() {
        PS18SigSchemePerfTestParamGen paramGen = new PS18SigSchemePerfTestParamGen(40);
        psScheme = paramGen.generateSigScheme();
        message = paramGen.generateMessage(2);
        keyPair = psScheme.generateKeyPair(2);
        sig = (PS18Signature) psScheme.sign(message, keyPair.getSigningKey());
    }

    @Test
    @JUnitPerfTest(durationMs = 15_000, warmUpMs = 5_000)
    public void testSignVerifySameMessage() {
        Signature tempSig = psScheme.sign(message, keyPair.getSigningKey());
        assertTrue(psScheme.verify(message, tempSig, keyPair.getVerificationKey()));
    }

    @Test
    @JUnitPerfTest(durationMs = 15_000, warmUpMs = 5_000)
    public void testVerifySameSignature() {
        assertTrue(psScheme.verify(message, sig, keyPair.getVerificationKey()));
    }
}
