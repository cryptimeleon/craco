package de.upb.crypto.craco.sig;

import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.craco.common.PublicParameters;
import de.upb.crypto.craco.sig.hashthensign.params.HashThenSignParams;

/**
 * Parameter for a signature scheme test. These parameters can be reused to instantiate {@link HashThenSignParams} to
 * test the signature scheme in the {@link de.upb.crypto.craco.hashthensign.HashThenSign} construction.
 */
public class SignatureSchemeParams {
    private SignatureScheme signatureScheme;
    /**
     * This field is optional. i.e. {@code null}  iff {@link #signatureScheme} does not make use of
     * {@link PublicParameters}.
     */
    private PublicParameters publicParameters;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair1;
    private SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair2;
    private PlainText message1;
    private PlainText message2;

    public SignatureSchemeParams(SignatureScheme signatureScheme, PublicParameters publicParameters, PlainText message1,
                                 PlainText message2,
                                 SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair1,
                                 SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair2) {
        this.publicParameters = publicParameters;
        this.message1 = message1;
        this.signatureScheme = signatureScheme;
        this.keyPair1 = keyPair1;
        this.keyPair2 = keyPair2;
        this.message2 = message2;
    }

    public SignatureScheme getSignatureScheme() {
        return signatureScheme;
    }

    public PublicParameters getPublicParameters() {
        return publicParameters;
    }

    public SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> getKeyPair1() {
        return keyPair1;
    }

    public SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> getKeyPair2() {
        return keyPair2;
    }

    public PlainText getMessage1() {
        return message1;
    }

    public PlainText getMessage2() {
        return message2;
    }
}
