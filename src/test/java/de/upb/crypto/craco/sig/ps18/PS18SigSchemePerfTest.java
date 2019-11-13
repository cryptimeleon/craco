package de.upb.crypto.craco.sig.ps18;

import com.github.noconnor.junitperf.JUnitPerfRule;
import com.github.noconnor.junitperf.JUnitPerfTest;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import org.junit.*;

import static org.junit.Assert.assertTrue;

@Ignore
public class PS18SigSchemePerfTest {

    private static PS18SignatureScheme psScheme;
    private static PS18SignatureSchemeExpr psSchemeExpr;
    private static MessageBlock message;
    private static SignatureKeyPair<? extends PS18VerificationKey, ? extends PS18SigningKey>
            keyPair;
    private static PS18Signature sig;

    @Rule
    public JUnitPerfRule perfTestRule = new JUnitPerfRule();

    @BeforeClass
    public static void setUp() {
        PS18SigSchemePerfTestParamGen paramGen = new PS18SigSchemePerfTestParamGen(160);
        psScheme = paramGen.generateSigScheme();
        psSchemeExpr = paramGen.generateSigSchemeExpr();
        message = paramGen.generateMessage(15);
        keyPair = psScheme.generateKeyPair(15);
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
    public void testSignVerifySameMessageExpr() {
        Signature tempSig = psSchemeExpr.sign(message, keyPair.getSigningKey());
        assertTrue(psSchemeExpr.verify(message, tempSig, keyPair.getVerificationKey()));
    }

    @Test
    @JUnitPerfTest(durationMs = 15_000, warmUpMs = 5_000)
    public void testVerifySameSignature() {
        assertTrue(psScheme.verify(message, sig, keyPair.getVerificationKey()));
    }

    @Test
    @JUnitPerfTest(durationMs = 15_000, warmUpMs = 5_000)
    public void testVerifySameSignatureExpr() {
        assertTrue(psSchemeExpr.verify(message, sig, keyPair.getVerificationKey()));
    }
}
