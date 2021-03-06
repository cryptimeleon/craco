package org.cryptimeleon.craco.sig.hashthensign;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.craco.sig.SignatureScheme;
import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.craco.sig.VerificationKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.HashFunction;
import org.cryptimeleon.math.hash.impl.VariableOutputLengthHashFunction;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

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
            throw new IllegalArgumentException("The given hash function is incompatible with the given signature scheme! The output length is too large.");
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
    public PlainText restorePlainText(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public Signature restoreSignature(Representation repr) {
        return encapsulatedScheme.restoreSignature(repr);
    }

    @Override
    public SigningKey restoreSigningKey(Representation repr) {
        return encapsulatedScheme.restoreSigningKey(repr);
    }

    @Override
    public VerificationKey restoreVerificationKey(Representation repr) {
        return encapsulatedScheme.restoreVerificationKey(repr);
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
