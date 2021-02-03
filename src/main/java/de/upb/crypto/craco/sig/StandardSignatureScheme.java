package de.upb.crypto.craco.sig;

/**
 * A {@link SignatureScheme} where anyone can generate a valid {@code SigningKey} and corresponding
 * {@code VerificationKey} themselves.
 */
public interface StandardSignatureScheme extends SignatureScheme {
    SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> generateKeyPair();
}
