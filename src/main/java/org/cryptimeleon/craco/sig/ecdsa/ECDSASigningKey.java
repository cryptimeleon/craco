package org.cryptimeleon.craco.sig.ecdsa;

import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.StringRepresentation;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import static org.cryptimeleon.craco.sig.ecdsa.ECDSASignatureScheme.ALGORITHM;

/**
 * Signing key of the {@link ECDSASignatureScheme}.
 * </br>
 * Essentially a wrapper around Java's {@link PrivateKey} to fit into the Cryptimeleon API and support simple serialization.
 */
public class ECDSASigningKey implements SigningKey, StandaloneRepresentable {

    private final PrivateKey key;

    public ECDSASigningKey(PrivateKey secretKey) {
        this.key = secretKey;
    }

    public ECDSASigningKey(Representation repr) {
        byte[] encodedKey = Base64.getDecoder().decode(((StringRepresentation) repr).get());
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encodedKey);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            this.key = keyFactory.generatePrivate(privKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    PrivateKey getKey() {
        return key;
    }

    @Override
    public Representation getRepresentation() {
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        return new StringRepresentation(encodedKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ECDSASigningKey that = (ECDSASigningKey) o;
        return Objects.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key);
    }
}
