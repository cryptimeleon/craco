package org.cryptimeleon.craco.sig;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.structures.cartesian.Vector;

/**
 * A {@code MultiMessageSignatureScheme} is one where the sign and verify algorithms take a list of messages as input
 * instead of a single message.
 * <p>
 * This is implemented as the special case of a single-message scheme
 * where the signed message is of type {@link MessageBlock}.
 * <p>
 * This interface introduces some helper methods for this case.
 */
public interface MultiMessageSignatureScheme extends SignatureScheme {

    /**
     * Signs multiple messages as a single unit.
     * @param secretKey key to sign with
     * @param plainTexts plaintexts to sign
     * @return signature over the given plaintexts
     */
    default Signature sign(SigningKey secretKey, PlainText... plainTexts) {
        return sign(new MessageBlock(plainTexts), secretKey);
    }

    /**
     * Verifies a signature for multiple messages.
     * @param publicKey key to use for verification
     * @param signature signature to verify
     * @param plainTexts plaintexts to verify signature for
     * @return true if verification succeeds, else false
     */
    default Boolean verify(VerificationKey publicKey, Signature signature, PlainText... plainTexts) {
        return verify(new MessageBlock(plainTexts), signature, publicKey);
    }

    /**
     * Signs the given vector of plaintexts.
     * @param secretKey key to sign with
     * @param plainTexts plaintexts to sign
     * @return signature over the given vector of plaintexts
     */
    default Signature sign(SigningKey secretKey, Vector<? extends PlainText> plainTexts) {
        return sign(new MessageBlock(plainTexts), secretKey);
    }

    /**
     * Verifies a signature for a vector of plaintexts.
     * @param publicKey key to use for verification
     * @param signature signature to verify
     * @param plainTexts vector of plaintexts to verify signature for
     * @return true if verification succeeds, else false
     */
    default Boolean verify(VerificationKey publicKey, Signature signature, Vector<? extends PlainText> plainTexts) {
        return verify(new MessageBlock(plainTexts), signature, publicKey);
    }
}
