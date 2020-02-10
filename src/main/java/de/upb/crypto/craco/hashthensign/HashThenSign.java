package de.upb.crypto.craco.hashthensign;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.sig.interfaces.Signature;
import de.upb.crypto.craco.sig.interfaces.SignatureScheme;
import de.upb.crypto.craco.sig.interfaces.SigningKey;
import de.upb.crypto.craco.sig.interfaces.VerificationKey;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

/**
 * Simple implementation of the hash-then-sign paradigm, where the hashFunction will be used to hash the plaintext
 * before verifying it with the signature scheme.
 *
 * @author Mirko Jürgens
 */
public class HashThenSign implements SignatureScheme {

    private SignatureScheme encapsulatedScheme;

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
        hashFunction = (HashFunction) repr.obj().get("hashFunction").repr().recreateRepresentable();
        encapsulatedScheme = (SignatureScheme) repr.obj().get("signatureScheme").repr().recreateRepresentable();
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = new ObjectRepresentation();
        representation.put("signatureScheme", new RepresentableRepresentation(encapsulatedScheme));
        representation.put("hashFunction", new RepresentableRepresentation(hashFunction));
        return representation;
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
        if (encapsulatedScheme == null) {
            if (other.encapsulatedScheme != null)
                return false;
        } else if (!encapsulatedScheme.equals(other.encapsulatedScheme))
            return false;
        if (hashFunction == null) {
            if (other.hashFunction != null)
                return false;
        } else if (!hashFunction.equals(other.hashFunction))
            return false;
        return true;
    }

}
