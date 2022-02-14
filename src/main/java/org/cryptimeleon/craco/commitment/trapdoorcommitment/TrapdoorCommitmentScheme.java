package org.cryptimeleon.craco.commitment.trapdoorcommitment;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.RepresentationRestorer;

import java.lang.reflect.Type;

/**
 * Interface used to implement trapdoor commitment schemes.
 *
 * TODO currently this does not use the existing {@link CommitmentScheme} interface
 *      because it doesn't use a commitment key when committing to a value.
 *
 * TODO generate Tests for this package
 *
 * Based on the description given by [1]
 *
 * [1] Groth, J.: Homomorphic Trapdoor Commitments to Group Elements. 2009
 * https://eprint.iacr.org/2009/007.pdf
 *
 */
public interface TrapdoorCommitmentScheme extends StandaloneRepresentable, RepresentationRestorer {

    /**
     * Creates a key pair consisting of a commitment key and a trapdoor key
     *
     * @return the {@link TrapdoorCommitmentKeyPair} containing the {@link OpenValue} and {@link TrapdoorKey}
     *         associated with the scheme
     * */
    TrapdoorCommitmentKeyPair<? extends OpenValue, ? extends TrapdoorKey> generateKeyPair();

    /**
     * Creates a commitment to the given {@link PlainText}, using the given {@link CommitmentKey}.
     *
     * @param plainText the message to commit to
     * @param commitmentKey the commitment key to use
     *
     * @return the {@link CommitmentPair} containing the commitment and an {@link OpenValue} that can be used to
     *         reveal the committed message.
     */
    CommitmentPair commit(PlainText plainText, CommitmentKey commitmentKey);

    /**
     * Verifies that the given announced {@link PlainText} equals the result of opening
     * the {@link Commitment} with the {@link OpenValue}.
     * <p>
     * A commitment scheme such as {@link HashThenCommitCommitmentScheme} may also hash the message before committing
     * to it. This method can take this into account, i.e. by hashing the given announced plaintext before comparing.
     *
     * @param commitment commitment to verify
     * @param commitmentKey the commitment key to use
     * @param openValue used to open the commitment and reveal the content
     * @param plainText the hash of this will be compared with the opened commitment message
     * @return true if verification succeeds, else false
     */
    boolean verify(PlainText plainText, CommitmentKey commitmentKey, Commitment commitment, OpenValue openValue);

    /**
     * Samples the public parameters to create a pair of a commitment and an equivocation key.
     *
     * @return the {@link TrapdoorCommitmentPair} containing the commitment and an {@link EquivocationKey}
     *         that can be used to reveal the committed message.
     * */
    TrapdoorCommitmentPair trapdoorCommit();

    /**
     * Uses an equivocation and a trapdoor key to generate an opening for a given message {@link PlainText}
     *
     * @param plainText the message to find an opening to
     * @param equivocationKey the equivocation key to use
     * @param trapdoorKey the trapdoor key to use
     *
     * @return an opening to plainText that passes verification
     * */
    OpenValue trapdoorOpen(PlainText plainText, EquivocationKey equivocationKey, TrapdoorKey trapdoorKey);




    /**
     * Provides an injective mapping of the given {@code byte[]} to a {@link PlainText} usable with this scheme
     * (which may be a {@link MessageBlock}).
     * It only guarantees injectivity for arrays of the same length.
     * Applications that would like to use {@code mapToPlaintext} with multiple different array lengths
     * may want to devise a padding method and then only call mapToPlaintext with
     * byte arrays of the same (padded) length.
     *
     * @param bytes {@code byte[]} to map to a {@code PlainText} that can be committed to using this commitment scheme
     * @return {@code PlainText} usable with this commitment scheme
     * @throws IllegalArgumentException if there is no injective {@code PlainText} element corresponding to the given
     *                                  bytes, for example if the byte array is too long
     */
    PlainText mapToPlainText(byte[] bytes);


    default CommitmentPair restoreCommitmentPair(Representation repr) {
        return new CommitmentPair(
                restoreCommitment(repr.obj().get("com")),
                restoreOpenValue(repr.obj().get("open")));
    }

    default TrapdoorCommitmentPair restoreTrapdoorCommitmentPair(Representation repr) {
        return new TrapdoorCommitmentPair(
                restoreCommitment(repr.obj().get("com")),
                restoreTrapdoorValue(repr.obj().get("ek")));
    }

    Commitment restoreCommitment(Representation repr);

    OpenValue restoreOpenValue(Representation repr);

    EquivocationKey restoreTrapdoorValue(Representation repr);

    @Override
    default Object restoreFromRepresentation(Type type, Representation repr) {
        if (CommitmentPair.class.isAssignableFrom((Class) type))
            return restoreCommitmentPair(repr);
        if (Commitment.class.isAssignableFrom((Class) type))
            return restoreCommitment(repr);
        if (OpenValue.class.isAssignableFrom((Class) type))
            return restoreOpenValue(repr);

        throw new IllegalArgumentException("Commitment cannot restore type "+type.getTypeName());
    }

}
