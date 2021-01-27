package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.SignatureKeyPair;
import de.upb.crypto.craco.sig.SignatureSchemeTester;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class PSExtendedSignatureSchemeTest {
    private final int NUM_MESSAGES = 2;
    private final int SECURITY_PARAMETER = 260;

    private PSExtendedSignatureScheme psExtendedSignatureScheme;
    private SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> keyPair;
    private SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> wrongKeyPair;
    private PSPublicParameters pp;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;


    @Before
    public void setUp() {
        System.out.println("Setting up public parameters and public key...");
        PSPublicParametersGen ppSetup = new PSPublicParametersGen();
        pp = ppSetup.generatePublicParameter(SECURITY_PARAMETER, true);
        PSExtendedSignatureScheme scheme = new PSExtendedSignatureScheme(pp); // Using extended pk
        keyPair = scheme.generateKeyPair(NUM_MESSAGES); // Using extended pk
        do {
            wrongKeyPair = scheme.generateKeyPair(NUM_MESSAGES);
        } while (wrongKeyPair.getVerificationKey().equals(keyPair.getVerificationKey())
                || wrongKeyPair.getSigningKey().equals(keyPair.getSigningKey()));

        psExtendedSignatureScheme = new PSExtendedSignatureScheme(pp); // Using extended pk
        // Generate message blocks
        RingElementPlainText[] messages = new RingElementPlainText[NUM_MESSAGES];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = new RingElementPlainText(pp.getZp().getUniformlyRandomElement());
        }
        messageBlock = new MessageBlock(messages);
        RingElementPlainText[] wrongMessages = new RingElementPlainText[NUM_MESSAGES];
        for (int i = 0; i < wrongMessages.length; i++) {
            do {
                wrongMessages[i] = new RingElementPlainText(pp.getZp().getUniformlyRandomElement());
            } while (wrongMessages[i].equals(messages[i]));
        }
        wrongMessageBlock = new MessageBlock(wrongMessages);

    }

    @Test
    public void testPSSignatureSchemeSignAndVerify() {
        // signing a block of messages
        SignatureSchemeTester
                .testSignatureSchemeSignAndVerify(psExtendedSignatureScheme, messageBlock, keyPair.getVerificationKey(),
                        keyPair.getSigningKey());
    }

    @Test
    public void testPSSignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(psExtendedSignatureScheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey());

        // public parameter representation test
        PSPublicParameters ppTest;
        ppTest = new PSPublicParameters(pp.getRepresentation());
        Assert.assertEquals(pp, ppTest);
    }

    @Test
    public void testNegativeWrongMessagePSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongMessageSignatureSchemeSignAndVerify(psExtendedSignatureScheme,
                messageBlock, wrongMessageBlock, keyPair.getVerificationKey(), keyPair.getSigningKey());
    }

    @Test
    public void testNegativeWrongKeyPSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongKeysSignatureSchemeSignAndVerify(psExtendedSignatureScheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey(), wrongKeyPair.getVerificationKey(),
                wrongKeyPair.getSigningKey());
    }

    @Test
    public void testMapToPlaintext() {
        SignatureSchemeTester.testMapToPlaintext(psExtendedSignatureScheme, keyPair.getVerificationKey());
    }

    @Test
    public void testMapToPlaintextContract() {
        SignatureSchemeTester.testMapToPlainTextContract(psExtendedSignatureScheme, keyPair);
    }
}
