package de.upb.crypto.craco.commitment;

import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentSchemePublicParametersGen;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.stream.Collectors;

public class HashThenCommitCommitmentSchemeTest {

    private PedersenCommitmentScheme pedersenCommitmentScheme;
    private HashThenCommitCommitmentScheme hashThenCommitCommitmentScheme;
    private PlainText singleMessage;
    private MessageBlock originalMessageBlock;
    private MessageBlock wrongMessageBlock;

    @Before
    public void setUp() {
        PedersenCommitmentSchemePublicParametersGen pedersenCommitmentSchemePublicParametersGen = new
                PedersenCommitmentSchemePublicParametersGen();
        pedersenCommitmentScheme = new PedersenCommitmentScheme(pedersenCommitmentSchemePublicParametersGen.setup
                (260, 1, true));
        hashThenCommitCommitmentScheme = new HashThenCommitCommitmentScheme(pedersenCommitmentScheme,
                new SHA256HashFunction());

        // setup single message
        Zp zp = pedersenCommitmentScheme.getPp().getZp();
        singleMessage = new RingElementPlainText(zp.getUniformlyRandomElement());

        // setup for multiple messages
        // Construct Message Block
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
    public void testCommitmentSchemeSingleMessage() {
        CommitmentSchemeTester.testCommitmentSchemeVerify(hashThenCommitCommitmentScheme,
                hashThenCommitCommitmentScheme.mapToPlainText(singleMessage.getUniqueByteRepresentation()));
        // test mapToPlainText
        CommitmentSchemeTester.testCommitmentSchemeMapToPlaintext(hashThenCommitCommitmentScheme, singleMessage);
    }

    @Test
    public void testCommitmentSchemeMultipleMessages() {
        CommitmentSchemeTester.testCommitmentSchemeVerify(hashThenCommitCommitmentScheme,
                hashThenCommitCommitmentScheme.mapToPlainText(originalMessageBlock.getUniqueByteRepresentation()));
        // test mapToPlainText
        CommitmentSchemeTester.testCommitmentSchemeMapToPlaintext(hashThenCommitCommitmentScheme, originalMessageBlock);
    }


    @Test
    public void testVerifyOfWrongMessageBlock() {
        CommitmentSchemeTester.testCommitmentSchemeVerifyWithWrongMessages(hashThenCommitCommitmentScheme,
                hashThenCommitCommitmentScheme.mapToPlainText(originalMessageBlock.getUniqueByteRepresentation()),
                hashThenCommitCommitmentScheme.mapToPlainText(wrongMessageBlock.getUniqueByteRepresentation()));
        // test mapToPlainText
        CommitmentSchemeTester.testCommitmentSchemeMapToPlainTextWithWrongMessages(hashThenCommitCommitmentScheme,
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
