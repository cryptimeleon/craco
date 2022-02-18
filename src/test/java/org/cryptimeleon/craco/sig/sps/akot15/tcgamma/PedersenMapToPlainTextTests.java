package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.CommitmentSchemeTester;
import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

//TODO wait for external fix
public class PedersenMapToPlainTextTests {

    PedersenCommitmentScheme scheme;
    Zp zp;
    MessageBlock message;

    int SECURITY_PARAMETER = 128;
    int NUM_MESSAGES = 32;

    /**
     * Generates an instance of a {@link PedersenCommitmentScheme} for testing, as well as an appropriate message block
     * */
    //@Before
    public void setup(){

        DebugBilinearGroup bilinearGroup = new DebugBilinearGroup(
                RandomGenerator.getRandomPrime(SECURITY_PARAMETER),
                BilinearGroup.Type.TYPE_3
        );
        scheme = new PedersenCommitmentScheme(bilinearGroup.getG1(), NUM_MESSAGES);

        zp = new Zp(bilinearGroup.getG1().size());

        RingElementPlainText[] messageElements = new RingElementPlainText[NUM_MESSAGES];

        for (int i = 0; i < NUM_MESSAGES; i++) {
            messageElements[i] = new RingElementPlainText(zp.getUniformlyRandomElement());
        }

        message = new MessageBlock(messageElements);
    }

    /**
     * The minimal setup to reproduce the issue
     */
    //@Test
    public void testMinimalMapToPlainTextIssue() {
        try{
            RingElementPlainText testPlainText = new RingElementPlainText(zp.getUniformlyRandomElement());
            byte[] byteRepresentation = testPlainText.getUniqueByteRepresentation();

            //the array length this function expects does not match byteRepresentation.length
            Zp.ZpElement injectiveValue = zp.injectiveValueOf(byteRepresentation);
        }
        catch (IllegalArgumentException e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * The issue breaks the mapToPlainText function for the existing implementation of Pedersen Commitments
     */
    //@Test
    public void checkPedersenMapToPlainText() {
        try{
            CommitmentSchemeTester.testCommitmentSchemeMapToPlaintext(scheme, message);
        }
        catch (IllegalArgumentException e) {
            Assert.fail(e.getMessage());
        }
    }

}
