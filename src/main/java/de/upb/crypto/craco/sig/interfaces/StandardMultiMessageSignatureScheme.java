package de.upb.crypto.craco.sig.interfaces;

/**
 * A combination of {@link MultiMessageSignatureScheme} and {@link StandardSignatureScheme} resulting in
 * a multi-message scheme with key generation functions.
 */
public interface StandardMultiMessageSignatureScheme extends StandardSignatureScheme, MultiMessageSignatureScheme {
    /**
     * Generates a key pair for signing a block of {@code numberOfMessages} messages
     * with each signature.
     *
     * @param numberOfMessages the number of messages as input to sign supported by this key pair
     */
    SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> generateKeyPair(int numberOfMessages);

    /**
     * Generates a key pair for signing a single message.
     */
    @Override
    default SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> generateKeyPair() {
        return generateKeyPair(1);
    }
}
