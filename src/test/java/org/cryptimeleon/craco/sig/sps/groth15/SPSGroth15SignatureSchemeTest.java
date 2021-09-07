package org.cryptimeleon.craco.sig.sps.groth15;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.*;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * JUnit test for the Groth15 SPS scheme
 */

public class SPSGroth15SignatureSchemeTest {
    static long timerStart = 0;
    static int testIterations = 1;
    private final int NUM_MESSAGES = 2;
    private final int SECURITY_PARAMETER = 128;

    private SPSGroth15SignatureScheme scheme;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> wrongKeyPair;
    private SPSGroth15PublicParameters pp;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;

    protected static void measureTime(String str) {
        if (timerStart == 0) {
            timerStart = System.currentTimeMillis();
        } else {
            long end = System.currentTimeMillis();
            System.out.println(str + ": " + ((end - timerStart) / 1000) + "s, " + ((end - timerStart) % 1000) + "ms");
            timerStart = 0;
        }
    }

    @Before
    public void setUp() throws Exception {
        for (SPSGroth15PublicParametersGen.Groth15Type type : SPSGroth15PublicParametersGen.Groth15Type.values()) {
            for (int i = 0; i < 1; i++) {
                SignatureSchemeParams params =
                        SPSGroth15SignatureSchemeTestParamGenerator.generateParams(SECURITY_PARAMETER, type, NUM_MESSAGES);
                this.scheme = (SPSGroth15SignatureScheme) params.getSignatureScheme();
                this.keyPair = params.getKeyPair1();
                this.wrongKeyPair = params.getKeyPair2();
                this.pp = (SPSGroth15PublicParameters) params.getPublicParameters();
                this.messageBlock = (MessageBlock) params.getMessage1();
                this.wrongMessageBlock = (MessageBlock) params.getMessage2();
            }
        }
    }

    @Test
    public void testSPSGroth15SignatureSchemeSignAndVerify() {
        // signing a block of messages
        for (int i = 0; i < testIterations; i++) {
            SignatureSchemeTester.testSignatureSchemeSignAndVerify(scheme, messageBlock, keyPair.getVerificationKey(),
                    keyPair.getSigningKey());
        }
    }

    @Test
    public void testSPSGroth15SignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(scheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey());

        // public parameter representation test
        SPSGroth15PublicParameters ppTest;
        ppTest = new SPSGroth15PublicParameters(pp.getRepresentation(), pp.getPlaintextGroupGenerator().getStructure());
        assertEquals(pp, ppTest);
    }

    @Test
    public void testMapToPlaintext() {
        SignatureSchemeTester.testMapToPlaintext(scheme, keyPair.getVerificationKey());
    }

    @Test
    public void testMapToPlaintextContract() {
        SignatureSchemeTester.testMapToPlainTextContract(scheme, keyPair);
    }
}
