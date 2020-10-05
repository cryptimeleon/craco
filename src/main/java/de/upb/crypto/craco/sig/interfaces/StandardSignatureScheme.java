package de.upb.crypto.craco.sig.interfaces;

/**
 * A SignatureScheme where anyone can generate a valid SigningKey and corresponding
 * VerificationKey himself.
 */
public interface StandardSignatureScheme extends SignatureScheme {
    SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> generateKeyPair();
}
