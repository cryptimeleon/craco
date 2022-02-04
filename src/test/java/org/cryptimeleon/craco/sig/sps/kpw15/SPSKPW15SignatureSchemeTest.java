package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.SignatureSchemeTester;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class SPSKPW15SignatureSchemeTest {

    static int testIterations = 1;
    private final int NUM_MESSAGES = 1;
    private final int SECURITY_PARAMETER = 128;

    private SignatureSchemeParams params;

    @Before
    public void setUp() throws Exception {
        SignatureSchemeParams params =
                SPSKPW15SignatureSchemeTestParamGenerator.generateParams(SECURITY_PARAMETER, NUM_MESSAGES);

        this.params = params;
    }

    @Test
    public void testSign(){
        MessageBlock message = (MessageBlock) params.getMessage1();
        SPSKPW15SigningKey sk = (SPSKPW15SigningKey) params.getKeyPair1().getSigningKey();

        SPSKPW15SignatureScheme scheme = (SPSKPW15SignatureScheme) params.getSignatureScheme();

        SPSKPW15Signature sigma = (SPSKPW15Signature)scheme.sign(message, sk);

        System.out.println(sigma.hashCode());
    }

    @Test
    public void testSPSKPW15SignatureAndVerify() {
        // signing a block of messages
        for (int i = 0; i < testIterations; i++) {
            SignatureSchemeTester.testSignatureSchemeSignAndVerify(
                    params.getSignatureScheme(),
                    params.getMessage1(),
                    params.getKeyPair1().getVerificationKey(),
                    params.getKeyPair1().getSigningKey()
            );
        }
    }

    @Test
    public void testSPSKPW15SignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(
                params.getSignatureScheme(),
                params.getMessage1(),
                params.getKeyPair1().getVerificationKey(),
                params.getKeyPair1().getSigningKey()
        );

        // public parameter representation test
        SPSKPW15PublicParameters ppTest;
        ppTest = new SPSKPW15PublicParameters(params.getPublicParameters().getRepresentation());
        assertEquals(params.getPublicParameters(), ppTest);
    }

    @Test
    public void testMapToPlaintext() {
        SignatureSchemeTester.testMapToPlaintext(
                params.getSignatureScheme(),
                params.getKeyPair1().getVerificationKey());
    }

    @Test
    public void testMapToPlaintextContract() {

        SignatureSchemeTester.testMapToPlainTextContract(
                params.getSignatureScheme(),
                params.getKeyPair1()
        );
    }


}
