package de.upb.crypto.craco.sig.hashthensign;

import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.sig.Signature;
import de.upb.crypto.craco.sig.SignatureScheme;
import de.upb.crypto.craco.sig.SigningKey;
import de.upb.crypto.craco.sig.VerificationKey;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.HashFunction;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * Simple implementation of the hash-then-sign paradigm, where the given hash function will be used
 * to hash the plaintext before verifying it with the signature scheme.
 *
 *
 */
public class HashThenSign implements SignatureScheme {

    @Represented
    private SignatureScheme encapsulatedScheme;

    @Represented
    private HashFunction hashFunction;

    public HashThenSign(HashFunction hashFunction, SignatureScheme signatureScheme) {
        if (hashFunction.getOutputLength() > signatureScheme.getMaxNumberOfBytesForMapToPlaintext()) {
            throw new IllegalArgumentException(
                    "The given hash function is incompatible with the given signature scheme! The output length is " +
                            "too large.");
        }
        this.hashFunction = hashFunction;
        this.encapsulatedScheme = signatureScheme;
    }

    /**
     * This constructor instantiates the Hash-then-Sign construction with a suitable hash function for the given
     * signature scheme.
     * The default hash function used here is {@link VariableOutputLengthHashFunction}.
     */
    public HashThenSign(SignatureScheme signatureScheme) {
        this.hashFunction =
                new VariableOutputLengthHashFunction(signatureScheme.getMaxNumberOfBytesForMapToPlaintext());
        this.encapsulatedScheme = signatureScheme;
    }

    public HashThenSign(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Signature sign(ByteAccumulator plaintextBytes, SigningKey secretKey) {
        return this.sign(new ByteArrayImplementation(plaintextBytes.extractBytes()), secretKey);
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {
        if (!(plainText instanceof ByteArrayImplementation)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        // hash
        ByteArrayImplementation pt = (ByteArrayImplementation) plainText;
        byte[] hashedBytes = hashFunction.hash(pt.getData());
        PlainText hashedPlaintext = encapsulatedScheme.mapToPlaintext(hashedBytes, secretKey);
        //sign
        return encapsulatedScheme.sign(hashedPlaintext, secretKey);
    }

    public Boolean verify(ByteAccumulator plaintextBytes, Signature signature, VerificationKey publicKey) {
        return this.verify(new ByteArrayImplementation(plaintextBytes.extractBytes()), signature, publicKey);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {
        if (!(plainText instanceof ByteArrayImplementation)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        // hash
        ByteArrayImplementation pt = (ByteArrayImplementation) plainText;
        byte[] hashedBytes = hashFunction.hash(pt.getData());
        PlainText hashedPlaintext = encapsulatedScheme.mapToPlaintext(hashedBytes, publicKey);
        //verify
        return encapsulatedScheme.verify(hashedPlaintext, signature, publicKey);
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public Signature getSignature(Representation repr) {
        return encapsulatedScheme.getSignature(repr);
    }

    @Override
    public SigningKey getSigningKey(Representation repr) {
        return encapsulatedScheme.getSigningKey(repr);
    }

    @Override
    public VerificationKey getVerificationKey(Representation repr) {
        return encapsulatedScheme.getVerificationKey(repr);
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
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((encapsulatedScheme == null) ? 0 : encapsulatedScheme.hashCode());
        result = prime * result + ((hashFunction == null) ? 0 : hashFunction.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        HashThenSign other = (HashThenSign) obj;
        return Objects.equals(encapsulatedScheme, other.encapsulatedScheme)
                && Objects.equals(hashFunction, other.hashFunction);
    }
}
