package de.upb.crypto.craco.commitment;

import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentSchemePublicParametersGen;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.BigIntegerRepresentation;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

public class PedersenCommitmentSchemeTest {
    private static final int NUMBER_OF_TEST_MESSAGES = 3;
    private static final int LAMBDA = 260;
    private PedersenCommitmentSchemePublicParametersGen pedersenCommitmentSchemePublicParametersGen;
    private PedersenCommitmentScheme pedersenCommitmentSchemeSingleMessage;
    private PedersenCommitmentScheme pedersenCommitmentSchemeMultipleMessages;
    private RingElementPlainText singleMessage;
    private RingElementPlainText wrongSingleMessage;
    private MessageBlock singleMessageBlock;
    private MessageBlock originalMessageBlock;
    private MessageBlock wrongMessageBlock;

    @Before
    public void setUp() {
        pedersenCommitmentSchemePublicParametersGen = new PedersenCommitmentSchemePublicParametersGen();

        pedersenCommitmentSchemeSingleMessage =
                new PedersenCommitmentScheme(pedersenCommitmentSchemePublicParametersGen.setup(LAMBDA, 1, true));
        Zp zp = pedersenCommitmentSchemeSingleMessage.getPp().getZp();
        // setup for single message
        singleMessage = new RingElementPlainText(zp.getUniformlyRandomElement());
        singleMessageBlock = generateMessageBlock(new Zp.ZpElement[]{zp.getUniformlyRandomElement()});
        do {
            wrongSingleMessage = new RingElementPlainText(zp.getUniformlyRandomElement());
        } while (wrongSingleMessage.equals(singleMessage));

        // setup for multiple messages
        pedersenCommitmentSchemeMultipleMessages = new PedersenCommitmentScheme(
                pedersenCommitmentSchemePublicParametersGen.setup(LAMBDA, NUMBER_OF_TEST_MESSAGES, true));
        // Construct Message Block
        zp = new Zp(pedersenCommitmentSchemeMultipleMessages.getPp().getP());
        Zp.ZpElement message1 = zp.getUniformlyRandomElement();
        Zp.ZpElement message2 = zp.getUniformlyRandomElement();
        Zp.ZpElement message3 = zp.getUniformlyRandomElement();
        Zp.ZpElement wrongMessage;
        // Make sure the message is different from other messages (It's highly unlikely to get a repeated value for
        // wrongMessage but just in case)
        do {
            wrongMessage = zp.getUniformlyRandomElement();
        } while (wrongMessage.equals(message1) || wrongMessage.equals(message2) || wrongMessage.equals(message3));

        Zp.ZpElement[] originalMessages = new Zp.ZpElement[]{
                message1,
                message2,
                message3,
        };

        Zp.ZpElement[] wrongMessages = new Zp.ZpElement[]{
                message1,
                message2,
                wrongMessage,
        };

        originalMessageBlock = generateMessageBlock(originalMessages);
        wrongMessageBlock = generateMessageBlock(wrongMessages);
    }

    @Test
    public void checkPedersenCommitmentSingleMessage() {
        // test verify()
        CommitmentSchemeTester.testCommitmentSchemeVerify(pedersenCommitmentSchemeSingleMessage, singleMessage);
    }

    @Test
    public void checkPedersenCommitmentWithMessageBlock() {
        // test for verify()-method
        CommitmentSchemeTester.testCommitmentSchemeVerify(pedersenCommitmentSchemeMultipleMessages,
                originalMessageBlock);
    }

    /**
     * This test checks the correctness of the calculations inside the {@link PedersenCommitmentScheme} by comparison to
     * precalculated, fixed values.
     */
    @Test
    public void testCommitmentWithPredefinedSetup() {
        // Setup predefined value for PedersenPublicParameter object (h[],G,g,p)
        BigInteger p = BigInteger.valueOf(7);
        Zp zp = new Zp(p);
        Group group = zp.asAdditiveGroup();
        Zp.ZpElement zpTwo = zp.getOneElement().add(zp.getOneElement());
        Zp.ZpElement zpFour = zpTwo.add(zpTwo);

        GroupElement two = group.getElement(new BigIntegerRepresentation(BigInteger.valueOf(2)));
        GroupElement three = group.getElement(new BigIntegerRepresentation(BigInteger.valueOf(3)));

        GroupElement[] h = new GroupElement[]{
                three,
        };
        PedersenPublicParameters parameters = new PedersenPublicParameters(two, h, group);

        // Committing Message using r = zpTwo
        PedersenCommitmentScheme scheme = new FixedRValuePedersenCommitmentTestScheme(parameters);

        Zp.ZpElement[] origialMessages = new Zp.ZpElement[]{
                zpFour,
        };

        PedersenCommitmentPair pair = scheme.commit(generateMessageBlock(origialMessages));
        // expected value commitment value is (h being 0 based, m being 1 based):
        // c = h_0 ^ r + h_1 ^ m_1
        // c = 2^2 + 3^4 = 2*2 + 4*3 = 4 + 12 = 16 = 2 mod 7
        assertEquals(two, pair.getCommitmentValue().getCommitmentElement());
        assertEquals(zpTwo, pair.getOpenValue().getRandomValue());
    }


    @Test
    public void testOpeningOfWrongMessageBlock() {
        // test verify()-method
        CommitmentSchemeTester.testCommitmentSchemeVerifyWithWrongMessages(pedersenCommitmentSchemeMultipleMessages,
                originalMessageBlock, wrongMessageBlock);
    }

    /**
     * helper method
     *
     * @param messages Array of {@link Zp.ZpElement}
     * @return {@link MessageBlock}
     */
    private MessageBlock generateMessageBlock(Zp.ZpElement[] messages) {
        MessageBlock messageBlock = new MessageBlock();
        Arrays.stream(messages).map(RingElementPlainText::new).collect(Collectors.toCollection(() ->
                messageBlock));
        return messageBlock;
    }
}
