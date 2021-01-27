package de.upb.crypto.craco.enc.sym.streaming.aes;

import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.common.predicate.CiphertextIndex;
import de.upb.crypto.craco.common.predicate.KeyIndex;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.craco.enc.SymmetricKey;
import de.upb.crypto.craco.prf.PrfImage;
import de.upb.crypto.craco.prf.PrfKey;
import de.upb.crypto.craco.prf.PrfPreimage;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.random.RandomGenerator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Arrays;

/**
 * A simple implementation of an representable byte array. This byte array can
 * be a plain text or a cipher text or an encryption key and/or a decryption key
 *
 *
 */
public class ByteArrayImplementation implements PlainText, CipherText, DecryptionKey, EncryptionKey, SymmetricKey,
        KeyIndex, CiphertextIndex, PrfKey, PrfPreimage, PrfImage, UniqueByteRepresentable {

    @Represented
    private byte[] data;

    public ByteArrayImplementation(byte[] bytes) {
        this.data = bytes;
    }

    public ByteArrayImplementation(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    /**
     * Creates a new {@code ByteArrayImplementation} instance filled with {@code numberBytes} bytes of randomness
     *
     * @param numberBytes number of random bytes / length of resulting ByteArrayImplementation
     */
    public static ByteArrayImplementation fromRandom(int numberBytes) {
        return new ByteArrayImplementation(RandomGenerator.getRandomBytes(numberBytes));
    }

    public byte[] getData() {
        return data;
    }

    /**
     * Create new byte array as concatenation of {@code this} with {@code a}.
     *
     * @param a the array to append
     * @return the result of concatenation
     */
    public ByteArrayImplementation append(ByteArrayImplementation a) {
        byte[] result = new byte[data.length + a.getData().length];
        System.arraycopy(data, 0, result, 0, data.length);
        System.arraycopy(a, 0, result, data.length, a.getData().length);
        return new ByteArrayImplementation(result);
    }

    /**
     * Returns the length of this byte array.
     *
     * @return the length of this byte array
     */
    public int length() {
        return data.length;
    }

    /**
     * Compute exclusive or of two byte arrays.
     * <p>
     * Returns a new byte array where the i-th entry is the exclusive or of {@code this}
     * byte array's i-th entry and {@code a}'s i-th entry.
     *
     * @param a the argument to XOR {@code this} with
     * @return the result of XORing
     */
    public ByteArrayImplementation xor(ByteArrayImplementation a) {
        int min = Math.min(this.length(), a.length());
        int max = Math.max(this.length(), a.length());

        byte[] result = new byte[max];
        for (int i = 0; i < min; i++) {
            result[i] = (byte) (this.getData()[i] ^ a.getData()[i]);
        }
        return new ByteArrayImplementation(result);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(data);
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
        ByteArrayImplementation other = (ByteArrayImplementation) obj;
        return Arrays.equals(data, other.data);
    }

    @Override
    public String toString() {
        String result = "[";
        for (int i = 0; i < this.getData().length; i++) {
            result += String.format("%d", Byte.toUnsignedInt(this.getData()[i]));
            if (i < this.getData().length - 1)
                result += ",";
        }
        result += "]";
        return result;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndAppend(data);
        return accumulator;
    }
}
