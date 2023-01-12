package org.cryptimeleon.craco.commitment;

import org.cryptimeleon.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.RepresentationRestorer;

import java.lang.reflect.Type;

/**
 * Interface used to implement commitment schemes.
 */
public interface CommitmentScheme extends StandaloneRepresentable, RepresentationRestorer {

    /**
     * Creates a commitment to the given {@link PlainText}.
     *
     * @param plainText the message to commit to
     * @return the {@link CommitmentPair} containing the commitment and an {@link OpenValue} that can be used to
     *         reveal the committed message.
     */
    CommitmentPair commit(PlainText plainText);

    /**
     * Verifies that the given announced {@link PlainText} equals the result of opening
     * the {@link Commitment} with the {@link OpenValue}.
     * <p>
     * A commitment scheme such as {@link HashThenCommitCommitmentScheme} may also hash the message before committing
     * to it. This method can take this into account, i.e. by hashing the given announced plaintext before comparing.
     *
     * @param commitment commitment to verify
     * @param openValue used to open the commitment and reveal the content
     * @param plainText the hash of this will be compared with the opened commitment message
     * @return true if verification succeeds, else false
     */
    boolean verify(Commitment commitment, OpenValue openValue, PlainText plainText);

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
    PlainText mapToPlaintext(byte[] bytes);


    /**
     * Returns the maximal number of bytes that can be mapped injectively to a {@link PlainText} by
     * {@link #mapToPlaintext(byte[])}
     * <p>
     * As described in {@link #mapToPlaintext(byte[])} there might be no injective {@link PlainText} for some byte arrays, e.g.
     * if the byte array is too long. Therefore, this method provides the maximal number of bytes that can be mapped
     * injectively to a {@link PlainText}.
     *
     * @return maximal number of bytes that can be given to {@link #mapToPlaintext(byte[])}.
     */
    int getMaxNumberOfBytesForMapToPlaintext();

    default CommitmentPair restoreCommitmentPair(Representation repr) {
        return new CommitmentPair(
                restoreCommitment(repr.obj().get("com")),
                restoreOpenValue(repr.obj().get("open")));
    }

    Commitment restoreCommitment(Representation repr);

    OpenValue restoreOpenValue(Representation repr);

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
