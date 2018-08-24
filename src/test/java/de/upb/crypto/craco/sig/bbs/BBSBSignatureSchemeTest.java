package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.craco.sig.SignatureSchemeTester;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class BBSBSignatureSchemeTest {

    private BBSBSignatureScheme bbsScheme;
    private BBSBPublicParameter pp;
    private SignatureKeyPair<BBSBVerificationKey, BBSBSigningKey> keys;
    private SignatureKeyPair<BBSBVerificationKey, BBSBSigningKey> wrongKeys;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;

    @Before
    public void setUp() throws Exception {
        SignatureSchemeParams params = BBSSignatureSchemeTestParamGenerator.generateParams(80);
        this.bbsScheme = (BBSBSignatureScheme) params.getSignatureScheme();
        this.pp = (BBSBPublicParameter) params.getPublicParameters();
        this.keys = (SignatureKeyPair<BBSBVerificationKey, BBSBSigningKey>) params.getKeyPair1();
        this.wrongKeys = (SignatureKeyPair<BBSBVerificationKey, BBSBSigningKey>) params.getKeyPair2();
        this.messageBlock = (MessageBlock) params.getMessage1();
        this.wrongMessageBlock = (MessageBlock) params.getMessage2();
    }

    @Test
    public void testBBSSignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(bbsScheme, messageBlock, keys.getVerificationKey(), keys
                .getSigningKey());

        // public parameter test
        BBSBPublicParameter ppTest;
        ppTest = new BBSBPublicParameter(pp.getRepresentation());
        assertEquals(pp, ppTest);
    }

    @Test
    public void testBBSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testSignatureSchemeSignAndVerify(bbsScheme, messageBlock, keys.getVerificationKey(),
                keys.getSigningKey());
    }

    @Test
    public void testNegativeWrongMessagePSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongMessageSignatureSchemeSignAndVerify(bbsScheme,
                messageBlock, wrongMessageBlock, keys.getVerificationKey(), keys.getSigningKey());
    }

    @Test
    public void testNegativeWrongKeyPSSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongKeysSignatureSchemeSignAndVerify(bbsScheme, messageBlock,
                keys.getVerificationKey(), keys.getSigningKey(), wrongKeys.getVerificationKey(),
                wrongKeys.getSigningKey());
    }

    @Test
    public void testMapToPlaintext() {
        SignatureSchemeTester.testMapToPlaintext(bbsScheme, keys.getVerificationKey());
    }

    @Test
    public void testMapToPlaintextContract() {
        SignatureSchemeTester.testMapToPlainTextContract(bbsScheme, keys);
    }

}
