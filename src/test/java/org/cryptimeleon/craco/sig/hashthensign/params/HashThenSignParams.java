package org.cryptimeleon.craco.sig.hashthensign.params;

import org.cryptimeleon.craco.common.PublicParameters;
import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.hashthensign.HashThenSign;
import org.cryptimeleon.math.hash.HashFunction;

/**
 * {@link SignatureSchemeParams} extended by an {@link HashFunction} to specify an instance of the {@link HashThenSign}
 * construction for testing. {@link HashThenSign} works on bytes, therefore {@link SignatureSchemeParams#message1} and
 * {@link SignatureSchemeParams#message2} should always be set to (possibly random) {@link ByteArrayImplementation}.
 */
public class HashThenSignParams extends SignatureSchemeParams {
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
        // discards message1 and message2 contained in org.cryptimeleon.groupsig.params and replaces them by random bytes
        super(params.getSignatureScheme(), params.getPublicParameters()
                , ByteArrayImplementation.fromRandom(32), ByteArrayImplementation.fromRandom(32)
                , params.getKeyPair1(), params.getKeyPair2());
        this.hashFunction = hashFunction;
    }

    public HashFunction getHashFunction() {
        return hashFunction;
    }

}
