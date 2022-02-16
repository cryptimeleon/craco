package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.sig.SignatureSchemeParams;
import org.cryptimeleon.craco.sig.SignatureSchemeTester;
import org.cryptimeleon.craco.sig.sps.SPSSchemeTester;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 * Test class for the KPW15 SPS scheme
 * */
public class SPSKPW15SignatureSchemeTest extends SPSSchemeTester {

    @Override
    protected SignatureSchemeParams generateParameters() {
        return SPSKPW15SignatureSchemeTestParamGenerator.generateParams(SECURITY_PARAMETER, NUM_MESSAGES);
    }

    @Override
    public void testPublicParameterRepresentation() {
        // public parameter representation test
        SPSKPW15PublicParameters ppTest;
        ppTest = new SPSKPW15PublicParameters(params.getPublicParameters().getRepresentation());
        assertEquals(params.getPublicParameters(), ppTest);
    }

}
