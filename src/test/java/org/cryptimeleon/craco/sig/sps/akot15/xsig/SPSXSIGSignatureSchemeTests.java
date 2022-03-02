package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.sps.SPSSchemeTester;

import static org.junit.Assert.assertEquals;

public class SPSXSIGSignatureSchemeTests extends SPSSchemeTester {

    @Override
    protected SignatureSchemeParams generateParameters() {
        return SPSXSIGSignatureSchemeTestParamGenerator.generateParameters(SECURITY_PARAMETER, NUM_MESSAGES);
    }

    @Override
    public void testPublicParameterRepresentation() {
        // public parameter representation test
        SPSXSIGPublicParameters ppTest;
        ppTest = new SPSXSIGPublicParameters(params.getPublicParameters().getRepresentation());
        assertEquals(params.getPublicParameters(), ppTest);
    }

}
