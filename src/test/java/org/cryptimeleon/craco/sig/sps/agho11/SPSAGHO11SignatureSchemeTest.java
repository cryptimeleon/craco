package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.*;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SPSAGHO11SignatureSchemeTest {
    static long timerStart = 0;
    static int testIterations = 1;
    private final int NUM_MESSAGES = 2;
    private final int SECURITY_PARAMETER = 128;

    private SPSAGHO11SignatureScheme scheme;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> wrongKeyPair;
    private SPSAGHO11PublicParameters pp;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;

    private final Integer[] messageBlockLengths = new Integer[] {19, 24};

    @Before
    public void setUp() throws Exception {

        SignatureSchemeParams params =
                SPSAGHO11SignatureSchemeTestParamGenerator.generateParams(SECURITY_PARAMETER, messageBlockLengths);

        this.scheme = (SPSAGHO11SignatureScheme) params.getSignatureScheme();
        this.keyPair = params.getKeyPair1();
        this.wrongKeyPair = params.getKeyPair2();
        this.pp = (SPSAGHO11PublicParameters) params.getPublicParameters();
        this.messageBlock = (MessageBlock) params.getMessage1();
        this.wrongMessageBlock = (MessageBlock) params.getMessage2();

    }

    @Test
    public void testSPSAGHO11SignatureSchemeAndVerify() {
        // signing a block of messages
        for (int i = 0; i < testIterations; i++) {
            SignatureSchemeTester.testSignatureSchemeSignAndVerify(scheme, messageBlock, keyPair.getVerificationKey(), keyPair.getSigningKey());
        }
    }

    @Test
    public void testSPSAGHO11SignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(
                scheme,
                messageBlock,
                keyPair.getVerificationKey(),
                keyPair.getSigningKey()
        );

        // public parameter representation test
        SPSAGHO11PublicParameters ppTest;
        ppTest = new SPSAGHO11PublicParameters(pp.getRepresentation());
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
