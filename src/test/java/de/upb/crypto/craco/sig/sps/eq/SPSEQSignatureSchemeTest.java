package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.SignatureSchemeTester;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignatureScheme;
import de.upb.crypto.math.pairings.debug.DebugBilinearMap;
import de.upb.crypto.math.pairings.debug.DebugGroupLogger;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.Before;
import org.junit.Test;

import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * JUnit test for the SPS-EQ scheme
 */

public class SPSEQSignatureSchemeTest {
    static long timerStart = 0;
    private final int NUM_MESSAGES = 2;
    private final int SECURITY_PARAMETER = 256;

    private SPSEQSignatureScheme spseqScheme;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> wrongKeyPair;
    private SPSEQPublicParameters pp;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;

    @Before
    public void setUp() throws Exception {
        for (int i = 0; i < 50; i++) {
            SignatureSchemeParams params =
                    SPSEQSignatureSchemeTestParamGenerator.generateParams(SECURITY_PARAMETER, NUM_MESSAGES);
            this.spseqScheme = (SPSEQSignatureScheme) params.getSignatureScheme();
            this.keyPair = params.getKeyPair1();
            this.wrongKeyPair = params.getKeyPair2();
            this.pp = (SPSEQPublicParameters) params.getPublicParameters();
            this.messageBlock = (MessageBlock) params.getMessage1();
            this.wrongMessageBlock = (MessageBlock) params.getMessage2();
        }
    }

    @Test
    public void testSPSEQSignatureSchemeSignAndVerify() {
        // signing a block of messages
        for (int i = 0; i < 50; i++) {
            SignatureSchemeTester.testSignatureSchemeSignAndVerify(spseqScheme, messageBlock, keyPair.getVerificationKey(),
                    keyPair.getSigningKey());

        }
    }

    @Test
    public void testSPSEQSignatureSchemeChgRep() {
        // signing a block of messages
        for (int i = 0; i < 50; i++) {
            SPSEQSignature sigma = (SPSEQSignature) SignatureSchemeTester.testSignatureSchemeSignAndVerify(spseqScheme, messageBlock, keyPair.getVerificationKey(),
                    keyPair.getSigningKey());
            Zp.ZpElement mu = pp.getZp().getUniformlyRandomUnit();
            // change representative of signature
            measureTime(null);
            SPSEQSignature sigmaChgRep = (SPSEQSignature) spseqScheme.chgRep(messageBlock, sigma, mu, keyPair.getVerificationKey());
            measureTime("ChgRep");
            // change representative of message
            MessageBlock msg = new MessageBlock(messageBlock.parallelStream().map(m -> ((GroupElementPlainText) m).get().pow(mu)).
                    map(GroupElementPlainText::new).collect(Collectors.toList()));
            assertTrue(spseqScheme.verify(msg, sigmaChgRep,keyPair.getVerificationKey()));
        }
    }

    @Test
    public void testSPSEQSignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(spseqScheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey());

        // public parameter representation test
        SPSEQPublicParameters ppTest;
        ppTest = new SPSEQPublicParameters(pp.getBilinearMap().getG1(), pp.getBilinearMap().getG2(), pp.getRepresentation());
        assertEquals(pp, ppTest);
    }

    protected static void measureTime(String str) {
        if (timerStart == 0) {
            DebugGroupLogger.reset();
            timerStart = System.currentTimeMillis();
        } else {
            long end = System.currentTimeMillis();
            System.out.println(str + ": " + ((end - timerStart) / 1000) + "s, " + ((end - timerStart) % 1000) + "ms");
            timerStart = 0;
        }
    }
}
