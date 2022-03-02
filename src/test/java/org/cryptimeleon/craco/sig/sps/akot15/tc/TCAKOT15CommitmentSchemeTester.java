package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.CommitmentSchemeTester;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15Commitment;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.Group;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

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

    @Test
    public void testCommitmentSchemeRepresentationText() {

        AKOT15SharedPublicParameters pp = (AKOT15SharedPublicParameters)params.getPublicParameters();

        // Test representation of the scheme
        CommitmentPair comPair = params.getScheme().commit(params.getPlainText());
        Representation comPairRepr = comPair.getRepresentation();

        ObjectRepresentation objRepr = (ObjectRepresentation) comPairRepr;

        Group tcgG2 = ((TCGAKOT15Commitment) comPair.getCommitment()).getGroup2ElementGu().getStructure();
        Group tcG1 = ((TCAKOT15OpenValue)comPair.getOpenValue()).group1ElementGamma.getStructure();
        Group tcG2 = ((TCAKOT15OpenValue)comPair.getOpenValue()).spsPosSignatures[0].getGroup2ElementR().getStructure();

        TCGAKOT15Commitment com = new TCGAKOT15Commitment(tcgG2, objRepr.get("com"));
        TCAKOT15OpenValue open = new TCAKOT15OpenValue(
                tcG1,
                tcG2,
                objRepr.get("open")
        );
        assertEquals(comPair.getOpenValue(), open);
        assertEquals(comPair.getCommitment(), com);
    }

    @Test
    public void testMapToPlaintext() {
        CommitmentSchemeTester.testCommitmentSchemeMapToPlaintext(params.getScheme());
    }

}
