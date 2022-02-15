package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.sps.SPSSchemeTester;

import static org.junit.Assert.assertEquals;

public class SPSAGHO11SignatureSchemeTest extends SPSSchemeTester {

    private Integer[] msgBlockLengths;

    @Override
    protected SignatureSchemeParams generateParameters() {
        msgBlockLengths = new Integer[] {NUM_MESSAGES, NUM_MESSAGES};
        return SPSAGHO11SignatureSchemeTestParamGenerator.generateParams(SECURITY_PARAMETER, msgBlockLengths);
    }

    @Override
    public void testPublicParameterRepresentation() {
        SPSAGHO11PublicParameters ppTest;
        ppTest = new SPSAGHO11PublicParameters(params.getPublicParameters().getRepresentation());

        assertEquals(params.getPublicParameters(), ppTest);
    }
}
