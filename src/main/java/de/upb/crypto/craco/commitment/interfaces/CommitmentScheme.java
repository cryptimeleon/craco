package de.upb.crypto.craco.commitment.interfaces;

import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * Interface reflecting the theoretical properties of 'Commitment Schemes' in combination with these interfaces:
 * {@link CommitmentSchemePublicParameters}, {@link CommitmentSchemePublicParametersGen}, {@link CommitmentPair},
 * {@link CommitmentValue} and {@link OpenValue}.
 */
public interface CommitmentScheme extends StandaloneRepresentable {

    /**
     * Committing to an original message ({@link PlainText}).
     *
     * @param plainText Original message ({@link PlainText}) that gets committed to.
     * @return The {@link CommitmentPair} for the original message containing the {@link CommitmentValue} of the
     * original message and the corresponding {@link OpenValue}.
     */
    CommitmentPair commit(PlainText plainText);

    /**
     * Verification that the 'announced' {@link PlainText} (message) equals the result of opening the
     * {@link CommitmentValue} with the {@link OpenValue} (original message).
     * This method verifying whether the original message that was committed to equals the announced message. This
     * functionality is for example useful in order to use hashing.
     *
     * @param commitmentValue {@link CommitmentValue} Commitment of the original message {@link PlainText}.
     * @param openValue       {@link OpenValue} for the commitment of the original message {@link PlainText}.
     * @param plainText       {@link PlainText} (announced message) to be verified against the original message.
     * @return Boolean value whether the opened message equals the announced message (true) or not (false).
     */
    boolean verify(CommitmentValue commitmentValue, OpenValue openValue, PlainText plainText);

    /**
     * Provides an injective mapping of the byte[] to a {@link PlainText} usable with this scheme (which may be a
     * MessageBlock).
     * It only guarantees injectivity for arrays of the same length. Applications that would like to use mapToPlaintext
     * with multiple different array lengths, may want to devise a padding method and then only call mapToPlaintext with
     * byte[] of the same (padded) length.
     * This method may throw an {@link IllegalArgumentException} if there is no injective {@link PlainText} element of
     * these bytes (e.g., the byte array is too long).
     *
     * @param bytes byte[] representation of the message to commit
     * @return Injective {@link PlainText} corresponding to the {@link CommitmentScheme}
     */
    PlainText mapToPlainText(byte[] bytes);
}
