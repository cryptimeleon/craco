package org.cryptimeleon.craco.sig.ecdsa;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.SignatureScheme;
import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StringRepresentation;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;


/**
 * Cryptimeleon wrapper for the ECDSA signature scheme.
 * Uses the curve and algorithms specified in the constants below.
 */
public class ECDSASignatureScheme implements SignatureScheme {

    static final String ALGORITHM = "EC";
    static final String CURVE = "secp256k1";
    private static final String SIGNING_ALGORITHM = "SHA256withECDSA";
    private final Signature signer;

    public ECDSASignatureScheme() {
        try {
            signer = Signature.getInstance(SIGNING_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public SignatureKeyPair<ECDSAVerificationKey, ECDSASigningKey> generateKeyPair() {
        try {
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            return new SignatureKeyPair<>(new ECDSAVerificationKey(keyPair.getPublic()), new ECDSASigningKey(keyPair.getPrivate()));
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

    }


    @Override
    public org.cryptimeleon.craco.sig.Signature sign(PlainText plainText, SigningKey secretKey) {
        ECDSASigningKey ecdsaSigningKey = (ECDSASigningKey) secretKey;

        try {
            signer.initSign(ecdsaSigningKey.getKey());
            signer.update(plainText.getUniqueByteRepresentation());
            return new ECDSASignature(signer.sign());
        } catch (InvalidKeyException e ) {
            e.printStackTrace();
            throw new IllegalArgumentException("Input secretKey must a valid " + ALGORITHM + " secret key");
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Boolean verify(PlainText plainText, org.cryptimeleon.craco.sig.Signature signature, VerificationKey publicKey) {
        ECDSAVerificationKey ecdsaVerificationKey = (ECDSAVerificationKey) publicKey;
        ECDSASignature ecdsaSignature = (ECDSASignature) signature;

        try {
            signer.initVerify(ecdsaVerificationKey.getKey());
            signer.update(plainText.getUniqueByteRepresentation());
            return signer.verify(ecdsaSignature.bytes);
        } catch (InvalidKeyException e ) {
            e.printStackTrace();
            throw new IllegalArgumentException("Input publicKey must a valid " + ALGORITHM + " public key");
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PlainText restorePlainText(Representation repr) {
        return new MessageBlock(repr, ByteArrayImplementation::new);
    }

    @Override
    public org.cryptimeleon.craco.sig.Signature restoreSignature(Representation repr) {
        return new ECDSASignature(repr);
    }

    @Override
    public SigningKey restoreSigningKey(Representation repr) {
        return new ECDSASigningKey(repr);
    }

    @Override
    public VerificationKey restoreVerificationKey(Representation repr) {
        return new ECDSAVerificationKey(repr);
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return new ByteArrayImplementation(bytes);
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        return new ByteArrayImplementation(bytes);
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return Integer.MAX_VALUE;
    }

    @Override
    public Representation getRepresentation() {
        return new StringRepresentation("");
    }

    /*
     * We need equals, hashcode and the Representation constructor to satisfy the SignatureScheme bounds for automated tests
     * All instances of ECDSASignatureSchemer are 'equal'.
     */

    public ECDSASignatureScheme(Representation repr) {
        this();
    }

    @Override
    public boolean equals(Object o) {
        return o != null && getClass() == o.getClass();
    }

    @Override
    public int hashCode() {
        return Objects.hash(19817349853L);
    }
}
