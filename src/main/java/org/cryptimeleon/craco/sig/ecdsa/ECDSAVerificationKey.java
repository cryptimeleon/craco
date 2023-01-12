package org.cryptimeleon.craco.sig.ecdsa;

import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StringRepresentation;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import static org.cryptimeleon.craco.sig.ecdsa.ECDSASignatureScheme.ALGORITHM;

public class ECDSAVerificationKey implements VerificationKey {

    private final PublicKey key;

    public ECDSAVerificationKey(PublicKey privateKey) {
        this.key = privateKey;
    }

    public ECDSAVerificationKey(Representation repr) {
        byte[] encodedKey = Base64.getDecoder().decode(((StringRepresentation) repr).get());
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedKey);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            this.key = keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    PublicKey getKey() {
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
        ECDSAVerificationKey that = (ECDSAVerificationKey) o;
        return Objects.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key);
    }
}
