package de.upb.crypto.craco.commitment;

import de.upb.crypto.craco.commitment.hashthencommit.HashThenCommitCommitmentScheme;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.RepresentationRestorer;

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
    PlainText mapToPlainText(byte[] bytes);

    default CommitmentPair getCommitmentPair(Representation repr) {
        return new CommitmentPair(
                getCommitment(repr.obj().get("com")),
                getOpenValue(repr.obj().get("open")));
    }

    Commitment getCommitment(Representation repr);

    OpenValue getOpenValue(Representation repr);

    @Override
    default Object recreateFromRepresentation(Type type, Representation repr) {
        if (CommitmentPair.class.isAssignableFrom((Class) type))
            return getCommitmentPair(repr);
        if (Commitment.class.isAssignableFrom((Class) type))
            return getCommitment(repr);
        if (OpenValue.class.isAssignableFrom((Class) type))
            return getOpenValue(repr);

        throw new IllegalArgumentException("Commitment cannot recreate type "+type.getTypeName());
    }
}
