package org.cryptimeleon.craco.sig.sps.akot15;

import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.sps.SPSSchemeTester;

import static org.junit.Assert.assertEquals;

public class SPSAKOT15SignatureSchemeTests extends SPSSchemeTester {

    @Override
    protected SignatureSchemeParams generateParameters() {
        return SPSAKOT15SignatureSchemeTestParameterGenerator.generateParameters(SECURITY_PARAMETER, NUM_MESSAGES);
    }

    @Override
    public void testPublicParameterRepresentation() {
        // public parameter representation test
        AKOT15SharedPublicParameters ppTest;
        ppTest = new AKOT15SharedPublicParameters(params.getPublicParameters().getRepresentation());
        assertEquals(params.getPublicParameters(), ppTest);
    }

}
