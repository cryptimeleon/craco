package de.upb.crypto.craco.commitment;

import de.upb.crypto.craco.commitment.interfaces.Commitment;
import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Objects;

/**
 * Wrapper class that allows committing to the hash of a message.
 */
public class HashThenCommitCommitmentScheme implements CommitmentScheme {

    @Represented
    private CommitmentScheme encapsulatedScheme;
    @Represented
    private HashFunction hashFunction;

    /**
     * Constructor for {@link HashThenCommitCommitmentScheme}.
     *
     * @param encapsulatedScheme single-message-{@link CommitmentScheme} which shall be used in combination with a
     *                           {@link HashFunction}
     * @param hashFunction       {@link HashFunction} used for hashing of the original message
     */
    public HashThenCommitCommitmentScheme(CommitmentScheme encapsulatedScheme, HashFunction hashFunction) {
        this.encapsulatedScheme = encapsulatedScheme;
        this.hashFunction = hashFunction;
    }

    /**
     * Constructor for a {@link HashThenCommitCommitmentScheme}-instance from a {@link Representation}.
     *
     * @param repr {@link Representation} of a {@link HashThenCommitCommitmentScheme} instance
     */
    public HashThenCommitCommitmentScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    /**
     * Returns a commitment to the hash of the given message, computed via the previously defined hash function.
     *
     * @param plainText {@link ByteArrayImplementation} of the message to be hashed.
     * @return commitment to the hashed input
     */
    @Override
    public CommitmentPair commit(PlainText plainText) {
        ByteArrayImplementation pt;
        if (!(plainText instanceof ByteArrayImplementation)) {
            pt = (ByteArrayImplementation) mapToPlainText(plainText.getUniqueByteRepresentation());
        } else {
            pt = (ByteArrayImplementation) plainText;
        }
        // hash
        byte[] hashedBytes = hashFunction.hash(pt.getData());
        PlainText hashedPlainText = encapsulatedScheme.mapToPlainText(hashedBytes);

        return encapsulatedScheme.commit(hashedPlainText);
    }

    /**
     * Verifies that the hash of the given announced {@link PlainText} equals the result of opening
     * the {@link Commitment} with the {@link OpenValue}.
     *
     * @param commitment commitment to verify
     * @param openValue used to open the commitment and reveal the content
     * @param plainText the hash of this will be compared with the opened commitment message
     * @return true if verification succeeds, else false
     */
    @Override
    public boolean verify(Commitment commitment, OpenValue openValue, PlainText plainText) {
        ByteArrayImplementation pt;
        if (!(plainText instanceof ByteArrayImplementation)) {
            pt = (ByteArrayImplementation) mapToPlainText(plainText.getUniqueByteRepresentation());
        } else {
            pt = (ByteArrayImplementation) plainText;
        }
        // hash
        byte[] hashedBytes = hashFunction.hash(pt.getData());
        PlainText hashedPlainText = encapsulatedScheme.mapToPlainText(hashedBytes);
        return encapsulatedScheme.verify(commitment, openValue, hashedPlainText);
    }

    @Override
    public PlainText mapToPlainText(byte[] bytes) throws IllegalArgumentException {
        return new ByteArrayImplementation(bytes);
    }

    @Override
    public Commitment getCommitment(Representation repr) {
        return encapsulatedScheme.getCommitment(repr);
    }

    @Override
    public OpenValue getOpenValue(Representation repr) {
        return encapsulatedScheme.getOpenValue(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HashThenCommitCommitmentScheme other = (HashThenCommitCommitmentScheme) o;
        return Objects.equals(encapsulatedScheme, other.encapsulatedScheme) &&
                Objects.equals(hashFunction, other.hashFunction);
    }

    @Override
    public int hashCode() {
        return Objects.hash(encapsulatedScheme, hashFunction);
    }
}
