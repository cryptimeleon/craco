package org.cryptimeleon.craco.sig.sps;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.sps.kpw15.SPSKPW15PublicParameters;
import org.cryptimeleon.craco.sig.sps.kpw15.SPSKPW15SignatureSchemeTestParamGenerator;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Generic implementation of SPS scheme tests.
 * */
public abstract class SPSSchemeTester {

    protected static int testIterations = 5;
    protected static int NUM_MESSAGES = 32;
    protected static int SECURITY_PARAMETER = 128;

    protected SignatureSchemeParams params;

    protected abstract SignatureSchemeParams generateParameters();


    @Before
    public void setUp() throws Exception {
        params = generateParameters();
    }

    @Test
    public void testSignatureAndVerify() {
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
    public void testNegativeSignatureAndVerify() {
        // signing a block of messages
        for (int i = 0; i < testIterations; i++) {
            SignatureSchemeTester.testNegativeWrongKeysSignatureSchemeSignAndVerify(
                    params.getSignatureScheme(),
                    params.getMessage1(),
                    params.getKeyPair1().getVerificationKey(),
                    params.getKeyPair1().getSigningKey(),
                    params.getKeyPair2().getVerificationKey(),
                    params.getKeyPair2().getSigningKey()
            );
        }
    }

    @Test
    public void testSignatureSchemeRepresentationText() {
        // Test standard signature scheme representations
        SignatureSchemeTester.testRepresentationSignatureScheme(
                params.getSignatureScheme(),
                params.getMessage1(),
                params.getKeyPair1().getVerificationKey(),
                params.getKeyPair1().getSigningKey()
        );
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

    @Test
    public abstract void testPublicParameterRepresentation();

}
