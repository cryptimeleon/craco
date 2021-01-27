package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.sig.*;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * JUnit test for the Pointcheval Sanders signature scheme.
 *
 *
 */

public class PSSignatureSchemeTest {
    private final int NUM_MESSAGES = 2;
    private final int SECURITY_PARAMETER = 160;

    private PSSignatureScheme psScheme;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> wrongKeyPair;
    private PSPublicParameters pp;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;

    @Before
    public void setUp() throws Exception {
        SignatureSchemeParams params =
                PSSignatureSchemeTestParamGenerator.generateParams(SECURITY_PARAMETER, NUM_MESSAGES);
        this.psScheme = (PSSignatureScheme) params.getSignatureScheme();
        this.keyPair = params.getKeyPair1();
        this.wrongKeyPair = params.getKeyPair2();
        this.pp = (PSPublicParameters) params.getPublicParameters();
        this.messageBlock = (MessageBlock) params.getMessage1();
        this.wrongMessageBlock = (MessageBlock) params.getMessage2();
    }

    @Test
    public void testPSSignatureSchemeSignAndVerify() {
        // signing a block of messages
        SignatureSchemeTester.testSignatureSchemeSignAndVerify(psScheme, messageBlock, keyPair.getVerificationKey(),
                keyPair.getSigningKey());
    }

    @Test
    public void testPSSignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(psScheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey());

        // public parameter representation test
        PSPublicParameters ppTest;
        ppTest = new PSPublicParameters(pp.getRepresentation());
        assertEquals(pp, ppTest);
    }

    @Test
    public void testNegativeWrongMessagePSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongMessageSignatureSchemeSignAndVerify(psScheme,
                messageBlock, wrongMessageBlock, keyPair.getVerificationKey(), keyPair.getSigningKey());
    }

    @Test
    public void testNegativeWrongKeyPSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongKeysSignatureSchemeSignAndVerify(psScheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey(), wrongKeyPair.getVerificationKey(),
                wrongKeyPair.getSigningKey());
    }

    @Test
    public void testMapToPlaintext() {
        SignatureSchemeTester.testMapToPlaintext(psScheme, keyPair.getVerificationKey());
    }

    @Test
    public void testMapToPlaintextContract() {
        SignatureSchemeTester.testMapToPlainTextContract(psScheme, keyPair);
    }
}
