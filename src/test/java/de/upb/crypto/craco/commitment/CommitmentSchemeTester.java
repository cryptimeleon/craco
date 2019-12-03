package de.upb.crypto.craco.commitment;

import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.Commitment;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.craco.interfaces.PlainText;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CommitmentSchemeTester {

    /**
     * Test that checks whether {@link CommitmentScheme#verify} returns true for the {@link Commitment} and
     * {@link OpenValue} of a
     * commitment to a message {@link CommitmentPair} if the ('announced') message ({@link PlainText}) equals the
     * message that leads to the given {@link CommitmentPair}.
     *
     * @param commitmentScheme {@link CommitmentScheme} whose (positive) correctness is to be tested
     * @param message          {@link PlainText} that is committed to in this test
     */
    public static void testCommitmentSchemeVerify(CommitmentScheme commitmentScheme, PlainText message) {
        CommitmentPair commitmentPair = commitmentScheme.commit(message);
        assertTrue(commitmentScheme.verify(commitmentPair.getCommitment(),
                commitmentPair.getOpenValue(), message));
    }

    /**
     * Test that checks whether {@link CommitmentScheme#verify} returns false for the {@link Commitment} and
     * {@link OpenValue} of
     * a commitment to a message {@link CommitmentPair} if the ('announced') message ({@link PlainText}) does not equal
     * the message that leads to the given {@link CommitmentPair}. For this test two inequal messages
     * ({@link PlainText}s) are being committed to and then it is checked that the verify returns false for all
     * combinations of {@link Commitment} and {@link OpenValue} that that do not match to the 'message'.
     *
     * @param commitmentScheme {@link CommitmentScheme} whose (negative) correctness is to be tested
     * @param originalMessage  {@link PlainText} that is committed to in this test
     * @param wrongMessage     Inequal {@link PlainText} to the originalMessage that is committed to in this test
     */
    public static void testCommitmentSchemeVerifyWithWrongMessages(CommitmentScheme commitmentScheme,
                                                                   PlainText originalMessage,
                                                                   PlainText wrongMessage) {
        CommitmentPair commitmentPair = commitmentScheme.commit(originalMessage);
        CommitmentPair commitmentPair2 = commitmentScheme.commit(wrongMessage);
        assertFalse(commitmentScheme.verify(commitmentPair.getCommitment(),
                commitmentPair.getOpenValue(), wrongMessage));
        assertFalse(commitmentScheme.verify(commitmentPair.getCommitment(),
                commitmentPair2.getOpenValue(), wrongMessage));
        assertFalse(commitmentScheme.verify(commitmentPair.getCommitment(),
                commitmentPair2.getOpenValue(), originalMessage));
        assertFalse(commitmentScheme.verify(commitmentPair2.getCommitment(),
                commitmentPair.getOpenValue(), wrongMessage));
        assertFalse(commitmentScheme.verify(commitmentPair2.getCommitment(),
                commitmentPair2.getOpenValue(), originalMessage));
    }

    /**
     * This test checks whether the usage of {@link CommitmentScheme#mapToPlainText} works correctly according to its
     * contract.
     *
     * @param commitmentScheme single-message {@link CommitmentScheme} whose mapToPlainText() is tested
     * @param message          {@link PlainText} that is committed to in this test
     */
    public static void testCommitmentSchemeMapToPlaintext(CommitmentScheme commitmentScheme, PlainText message) {
        CommitmentPair commitmentPair =
                commitmentScheme.commit(commitmentScheme.mapToPlainText(message.getUniqueByteRepresentation()));
        assertTrue(commitmentScheme.verify(commitmentPair.getCommitment(),
                commitmentPair.getOpenValue(), commitmentScheme.mapToPlainText(message.getUniqueByteRepresentation())));
    }

    /**
     * This test checks that the usage of {@link CommitmentScheme#mapToPlainText} works correctly according to its
     * contract.
     * Test checks that {@link CommitmentScheme#verify} returns false for the {@link Commitment} and
     * {@link OpenValue} of
     * a commitment to a message {@link CommitmentPair} if the ('announced') message ({@link PlainText}) does not equal
     * the message that leads to the given {@link CommitmentPair}. For this test two inequal messages
     * ({@link PlainText}s) are being committed to and then it is checked that the verify returns false for all
     * combinations of {@link Commitment} and {@link OpenValue} that that do not match to the 'message'.
     *
     * @param commitmentScheme {@link CommitmentScheme} whose (negative) correctness is to be tested
     * @param originalMessage  {@link PlainText} that is committed to in this test
     * @param wrongMessage     Inequal {@link PlainText} to the originalMessage that is committed to in this test
     */
    public static void testCommitmentSchemeMapToPlainTextWithWrongMessages(CommitmentScheme commitmentScheme,
                                                                           PlainText originalMessage,
                                                                           PlainText wrongMessage) {
        CommitmentPair commitmentPair =
                commitmentScheme.commit(commitmentScheme.mapToPlainText(originalMessage.getUniqueByteRepresentation()));
        CommitmentPair commitmentPair2 =
                commitmentScheme.commit(commitmentScheme.mapToPlainText(wrongMessage.getUniqueByteRepresentation()));
        assertFalse(commitmentScheme.verify(commitmentPair.getCommitment(),
                commitmentPair.getOpenValue(),
                commitmentScheme.mapToPlainText(wrongMessage.getUniqueByteRepresentation())));
        assertFalse(commitmentScheme.verify(commitmentPair.getCommitment(),
                commitmentPair2.getOpenValue(),
                commitmentScheme.mapToPlainText(wrongMessage.getUniqueByteRepresentation())));
        assertFalse(commitmentScheme.verify(commitmentPair.getCommitment(),
                commitmentPair2.getOpenValue(),
                commitmentScheme.mapToPlainText(originalMessage.getUniqueByteRepresentation())));
        assertFalse(commitmentScheme.verify(commitmentPair2.getCommitment(),
                commitmentPair.getOpenValue(),
                commitmentScheme.mapToPlainText(wrongMessage.getUniqueByteRepresentation())));
        assertFalse(commitmentScheme.verify(commitmentPair2.getCommitment(),
                commitmentPair2.getOpenValue(),
                commitmentScheme.mapToPlainText(originalMessage.getUniqueByteRepresentation())));
    }
}
