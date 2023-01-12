package org.cryptimeleon.craco.sig.ecdsa;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.*;
import org.junit.Before;
import org.junit.Test;

public class ECDSASignatureSchemeTest {
    private ECDSASignatureScheme scheme;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> wrongKeyPair;
    private MessageBlock messageBlock;
    private MessageBlock wrongMessageBlock;

    @Before
    public void setUp() {
        SignatureSchemeParams params = ECDSASignatureSchemeTestParamGen.generateParams();
        this.scheme = (ECDSASignatureScheme) params.getSignatureScheme();
        this.keyPair = params.getKeyPair1();
        this.wrongKeyPair = params.getKeyPair2();
        this.messageBlock = (MessageBlock) params.getMessage1();
        this.wrongMessageBlock = (MessageBlock) params.getMessage2();
    }

    @Test
    public void testSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testSignatureSchemeSignAndVerify(scheme, messageBlock, keyPair.getVerificationKey(),
                keyPair.getSigningKey());
    }

    @Test
    public void testSignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(scheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey());
    }

    @Test
    public void testNegativeWrongMessageSignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongMessageSignatureSchemeSignAndVerify(scheme,
                messageBlock, wrongMessageBlock, keyPair.getVerificationKey(), keyPair.getSigningKey());
    }

    @Test
    public void testNegativeWrongKeySignatureSchemeSignAndVerify() {
        SignatureSchemeTester.testNegativeWrongKeysSignatureSchemeSignAndVerify(scheme, messageBlock,
                keyPair.getVerificationKey(), keyPair.getSigningKey(), wrongKeyPair.getVerificationKey(),
                wrongKeyPair.getSigningKey());
    }
}
