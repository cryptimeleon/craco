package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.SignatureSchemeTester;
import de.upb.crypto.craco.sig.interfaces.SignatureKeyPair;
import de.upb.crypto.craco.sig.interfaces.SigningKey;
import de.upb.crypto.craco.sig.interfaces.VerificationKey;
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
    static int testIterations = 1;
    private final int NUM_MESSAGES = 2;
    private final int SECURITY_PARAMETER = 128;

    private SPSEQSignatureScheme spseqScheme;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> wrongKeyPair;
    private SPSEQPublicParameters pp;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;

    @Before
    public void setUp() throws Exception {
        for (int i = 0; i < 1; i++) {
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
        for (int i = 0; i < testIterations; i++) {
            SignatureSchemeTester.testSignatureSchemeSignAndVerify(spseqScheme, messageBlock, keyPair.getVerificationKey(),
                    keyPair.getSigningKey());
        }
    }

    @Test
    public void testSPSEQSignatureSchemeChgRep() {
        // signing a block of messages
        for (int i = 0; i < testIterations; i++) {
            SPSEQSignature sigma = (SPSEQSignature) SignatureSchemeTester.testSignatureSchemeSignAndVerify(spseqScheme, messageBlock, keyPair.getVerificationKey(),
                    keyPair.getSigningKey());
            Zp.ZpElement mu = pp.getZp().getUniformlyRandomUnit();
            // change representative of signature
            measureTime(null);
            SPSEQSignature sigmaChgRep = (SPSEQSignature) spseqScheme.chgRep(sigma, mu, keyPair.getVerificationKey());
            measureTime("ChgRep");
            // change representative of message
            MessageBlock msgChgRep= new MessageBlock(messageBlock.stream().map(m -> ((GroupElementPlainText) m).get().pow(mu)).
                    map(GroupElementPlainText::new).collect(Collectors.toList()));
            // check ChgRep
            assertTrue(spseqScheme.verify(msgChgRep, sigmaChgRep, keyPair.getVerificationKey()));
            // check ChgRepWithVerify
            sigmaChgRep = (SPSEQSignature) spseqScheme.chgRepWithVerify(messageBlock, sigma, mu, keyPair.getVerificationKey());
            PlainText msgChgRepMessage = spseqScheme.chgRepMessage(messageBlock, mu);
            assertTrue(spseqScheme.verify(msgChgRepMessage, sigmaChgRep, keyPair.getVerificationKey()));
            // check chpRepMessage
            assertTrue(msgChgRep.equals(msgChgRepMessage));
        }
    }

    @Test
    public void testSPSEQSignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(spseqScheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey());

        // public parameter representation test
        SPSEQPublicParameters ppTest;
        ppTest = new SPSEQPublicParameters(pp.getRepresentation());
        assertEquals(pp, ppTest);
    }

    @Test
    public void testMapToPlaintext() {
        SignatureSchemeTester.testMapToPlaintext(spseqScheme, keyPair.getVerificationKey());
    }

    @Test
    public void testMapToPlaintextContract() {
        SignatureSchemeTester.testMapToPlainTextContract(spseqScheme, keyPair);
    }

    protected static void measureTime(String str) {
        if (timerStart == 0) {
            timerStart = System.currentTimeMillis();
        } else {
            long end = System.currentTimeMillis();
            System.out.println(str + ": " + ((end - timerStart) / 1000) + "s, " + ((end - timerStart) % 1000) + "ms");
            timerStart = 0;
        }
    }
}
