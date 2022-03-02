package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.CommitmentSchemeTester;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.junit.Before;
import org.junit.Test;

public class TCGAKOT15CommitmentSchemeTests {

    private final int SECURITY_PARAMETER = 128;
    private final int MESSAGE_LENGTH = 1;


    TCGAKOT15TestParameters params;


    @Before
    public void generateParameters() {
        params = TCGAKOT15CommitmentSchemeTestParameterGenerator.generateParameters(SECURITY_PARAMETER, MESSAGE_LENGTH);
    }

    @Test
    public void testCommitAndVerify() {
        CommitmentSchemeTester.testCommitmentSchemeVerify(params.getScheme(), params.getPlainText());
    }

    @Test
    public void testCommitAndVerifyWithGroupElementMessage() {

        GroupElementPlainText[] gePlainText = ((MessageBlock)params.getPlainText()).stream().map
                (
                        x -> new GroupElementPlainText(((AKOT15SharedPublicParameters)params.getPublicParameters()).getG1GroupGenerator().pow(((RingElementPlainText)x).getRingElement()).compute())
                        ).toArray(GroupElementPlainText[]::new);


        MessageBlock groupElementPlainText = new MessageBlock(gePlainText);


        CommitmentPair com = params.getScheme().commit(params.getPlainText());

        params.getScheme().verify(com.getCommitment(), com.getOpenValue(), groupElementPlainText);
    }

    @Test
    public void testNegativeWrongCommitAndVerify() {
        CommitmentSchemeTester.testCommitmentSchemeVerifyWithWrongMessages(params.getScheme(), params.getPlainText(), params.getWrongPlainText());
    }

    @Test
    public void testMapToPlaintext() {
        CommitmentSchemeTester.testCommitmentSchemeMapToPlaintext(params.getScheme());
    }

}
