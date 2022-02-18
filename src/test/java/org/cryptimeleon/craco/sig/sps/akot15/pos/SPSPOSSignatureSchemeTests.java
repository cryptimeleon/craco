package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.SignatureSchemeTester;
import org.cryptimeleon.craco.sig.sps.SPSSchemeTester;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGPublicParameters;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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
            ((SPSPOSSignatureScheme)params.getSignatureScheme()).updateOneTimeKey((SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) params.getKeyPair1());
            ((SPSPOSSignatureScheme)params.getSignatureScheme()).updateOneTimeKey((SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) params.getKeyPair2());
        }
    }

    @Test
    public void testSignatureAndVerifyWithFixedOTKeys() {

        SPSPOSSignatureScheme scheme = (SPSPOSSignatureScheme) params.getSignatureScheme();

        Zp.ZpElement fixedSecretKey = ((AKOT15SharedPublicParameters)params.getPublicParameters()).getZp().getUniformlyRandomElement();
        GroupElement fixedPublicKey = ((AKOT15SharedPublicParameters)params.getPublicParameters()).getG1GroupGenerator().pow(fixedSecretKey).compute();

        SPSPOSSignature sigma = scheme.sign(params.getMessage1(), params.getKeyPair1().getSigningKey(), fixedSecretKey);

        assertTrue(scheme.verify(params.getMessage1(), sigma, params.getKeyPair1().getVerificationKey(), fixedPublicKey));
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
            ((SPSPOSSignatureScheme)params.getSignatureScheme()).updateOneTimeKey((SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) params.getKeyPair1());
            ((SPSPOSSignatureScheme)params.getSignatureScheme()).updateOneTimeKey((SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) params.getKeyPair2());
        }
    }

    @Test//(expected = IllegalStateException.class)
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
        AKOT15SharedPublicParameters ppTest;
        ppTest = new AKOT15SharedPublicParameters(params.getPublicParameters().getRepresentation());
        assertEquals(params.getPublicParameters(), ppTest);
    }

}
