package de.upb.crypto.craco.sig.hashthensign.params;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.hashthensign.HashThenSign;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.interfaces.signature.SignatureScheme;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.craco.sig.SignatureSchemeParams;
import de.upb.crypto.math.interfaces.hash.HashFunction;

/**
 * {@link SignatureSchemeParams} extended by an {@link HashFunction} to specify an instance of the {@link HashThenSign}
 * construction for testing. {@link HashThenSign} works on bytes, therefore {@link SignatureSchemeParams#message1} and
 * {@link SignatureSchemeParams#message2} should always be set to (possibly random) {@link ByteArrayImplementation}.
 */
public class HashThenSignParams extends de.upb.crypto.craco.sig.SignatureSchemeParams {
    private HashFunction hashFunction;

    HashThenSignParams(SignatureScheme signatureScheme, HashFunction hashFunction, PublicParameters publicParameters,
                       SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair1,
                       SignatureKeyPair<? extends VerificationKey, ? extends SigningKey> keyPair2) {
        super(signatureScheme, publicParameters
                , ByteArrayImplementation.fromRandom(32), ByteArrayImplementation.fromRandom(32)
                , keyPair1, keyPair2);
        this.hashFunction = hashFunction;
    }

    HashThenSignParams(SignatureSchemeParams params, HashFunction hashFunction) {
        // discards message1 and message2 contained in params and replaces them by random bytes
        super(params.getSignatureScheme(), params.getPublicParameters()
                , ByteArrayImplementation.fromRandom(32), ByteArrayImplementation.fromRandom(32)
                , params.getKeyPair1(), params.getKeyPair2());
        this.hashFunction = hashFunction;
    }

    public HashFunction getHashFunction() {
        return hashFunction;
    }

}
