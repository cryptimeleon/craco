package org.cryptimeleon.craco.commitment;

import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.SignatureScheme;
import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.debug.DebugGroup;

import java.util.Arrays;

import static org.junit.Assert.*;

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
     * This test checks whether the usage of {@link CommitmentScheme#mapToPlaintext} works correctly according to its
     * contract.
     *
     * @param commitmentScheme single-message {@link CommitmentScheme} whose mapToPlainText() is tested
     */
    public static void testCommitmentSchemeMapToPlaintext(CommitmentScheme commitmentScheme) {
        byte[] randomBytes1 = RandomGenerator.getRandomBytes(commitmentScheme.getMaxNumberOfBytesForMapToPlaintext());
        byte[] randomBytes2;
        do {
            randomBytes2 = RandomGenerator.getRandomBytes(commitmentScheme.getMaxNumberOfBytesForMapToPlaintext());
        } while (Arrays.equals(randomBytes1, randomBytes2));

        // different arrays of the same length yield different plaintext
        assertNotEquals(commitmentScheme.mapToPlaintext(randomBytes1), commitmentScheme.mapToPlaintext(randomBytes2));
    }

    public static void main(String[] args) {
        Group g = new DebugGroup("test", RandomGenerator.getRandomPrime(80));
        CommitmentScheme ped = new PedersenCommitmentScheme(g,10);
        CommitmentSchemeTester.testCommitmentSchemeMapToPlaintext(ped);



    }
}
