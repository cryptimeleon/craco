package de.upb.crypto.craco.commitment;

import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.Commitment;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Objects;

/**
 * Wrapper for a {@link CommitmentScheme} to be used with hashing of original message.
 */
public class HashThenCommitCommitmentScheme implements CommitmentScheme {

    @Represented
    private CommitmentScheme encapsulatedScheme;
    @Represented
    private HashFunction hashFunction;

    /**
     * Constructor for {@link HashThenCommitCommitmentScheme}
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
     * Constructor for a {@link HashThenCommitCommitmentScheme}-instance from a {@link Representation}
     *
     * @param repr {@link Representation} of a {@link HashThenCommitCommitmentScheme} instance.
     */
    public HashThenCommitCommitmentScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    /**
     * Commit with hashing, using the {@link HashFunction}
     *
     * @param plainText {@link ByteArrayImplementation} of the message to be hashed.
     * @return Commitment of the hashed input.
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
     * Verification that the 'announced' {@link PlainText} ( message) equals the result (original message) of opening
     * the {@link Commitment} with the {@link OpenValue} for hashing of the original message.
     *
     * @param commitment {@link Commitment} of the encapsulated {@link CommitmentScheme}.
     * @param openValue       {@link OpenValue} of the encapsulated {@link CommitmentScheme}.
     * @param plainText       {@link PlainText} (original message) of the encapsulated {@link CommitmentScheme}.
     * @return Boolean value whether the opened message equals the announced message is successful
     * (true) or not (false).
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

    /**
     * Casting method to generate a {@link PlainText} conforming a {@link ByteArrayImplementation}.
     *
     * @param bytes byte representation of the message to commit
     * @return {@link PlainText} conforming a {@link ByteArrayImplementation}
     */
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

    /**
     * The representation of this object. Used for serialization.
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
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
