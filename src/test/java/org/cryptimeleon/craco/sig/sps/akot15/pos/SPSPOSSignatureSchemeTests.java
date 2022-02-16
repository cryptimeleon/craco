package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.SignatureSchemeTester;
import org.cryptimeleon.craco.sig.sps.SPSSchemeTester;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGPublicParameters;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SPSPOSSignatureSchemeTests extends SPSSchemeTester {

    @Override
    protected SignatureSchemeParams generateParameters() {
        return SPSPOSSignatureSchemeTestParamGenerator.generateParameters(SECURITY_PARAMETER, NUM_MESSAGES);
    }

    @Override
    public void testSignatureAndVerify() {
        // signing a block of messages
        for (int i = 0; i < testIterations; i++) {
            SignatureSchemeTester.testSignatureSchemeSignAndVerify(
                    params.getSignatureScheme(),
                    params.getMessage1(),
                    params.getKeyPair1().getVerificationKey(),
                    params.getKeyPair1().getSigningKey()
            );
            // re-key one-time signature
            ((SPSPOSSignatureScheme)params.getSignatureScheme()).UpdateOneTimeKey((SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) params.getKeyPair1());
            ((SPSPOSSignatureScheme)params.getSignatureScheme()).UpdateOneTimeKey((SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) params.getKeyPair2());
        }
    }

    @Override
    public void testNegativeSignatureAndVerify() {
        // signing a block of messages
        for (int i = 0; i < testIterations; i++) {
            SignatureSchemeTester.testSignatureSchemeSignAndVerify(
                    params.getSignatureScheme(),
                    params.getMessage1(),
                    params.getKeyPair1().getVerificationKey(),
                    params.getKeyPair1().getSigningKey()
            );
            // re-key one-time signature
            ((SPSPOSSignatureScheme)params.getSignatureScheme()).UpdateOneTimeKey((SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) params.getKeyPair1());
            ((SPSPOSSignatureScheme)params.getSignatureScheme()).UpdateOneTimeKey((SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) params.getKeyPair2());
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testNegativeExpiredOTKeySignatureAndVerify() {
        // signing a block of messages, but without updating the one time key (which should give us an exception)
        for (int i = 0; i < testIterations; i++) {

            SignatureSchemeTester.testSignatureSchemeSignAndVerify(
                    params.getSignatureScheme(),
                    params.getMessage1(),
                    params.getKeyPair1().getVerificationKey(),
                    params.getKeyPair1().getSigningKey()
            );

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


    @Override
    public void testPublicParameterRepresentation() {
        // public parameter representation test
        SPSPOSPublicParameters ppTest;
        ppTest = new SPSPOSPublicParameters(params.getPublicParameters().getRepresentation());
        assertEquals(params.getPublicParameters(), ppTest);
    }

}
