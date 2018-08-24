package de.upb.crypto.craco.interfaces.signature;

/**
 * A standard signature scheme (where anyone can produce valid pk,sk pairs)
 * where the message space is a set of vectors of messages.
 * <p>
 * This is implemented as the special case of a single message scheme
 * where the signed message is of type MessageBlock.
 * <p>
 * generateKeyPair() without the numberOfMessages parameter defaults to a single message.
 */
public interface StandardMultiMessageSignatureScheme extends StandardSignatureScheme {
    /**
     * Generates a key pair for signing a vector of numberOfMessages messages
     * with each signature.
     *
     * @param numberOfMessages number of messages as input to sign supported by this key pair.
     */
    SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> generateKeyPair(int numberOfMessages);

    @Override
    default SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> generateKeyPair() {
        return generateKeyPair(1);
    }
}
