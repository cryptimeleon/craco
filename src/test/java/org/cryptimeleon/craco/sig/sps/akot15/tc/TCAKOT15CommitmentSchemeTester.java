package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.CommitmentSchemeTester;
import org.junit.Before;
import org.junit.Test;

public class TCAKOT15CommitmentSchemeTester {

    private final int SECURITY_PARAMETER = 128;
    private final int MESSAGE_LENGTH = 32;


    TrapdoorCommitmentTestParameters params;




    @Before
    public void generateParameters() {
        params = TCAKOT15CommitmentSchemeTestParameterGenerator.generateParameters(SECURITY_PARAMETER, MESSAGE_LENGTH);
    }

    @Test
    public void testCommitAndVerify() {
        CommitmentSchemeTester.testCommitmentSchemeVerify(params.getScheme(), params.getPlainText());
    }


}
