package org.cryptimeleon.craco.common;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.predicate.CiphertextIndex;
import org.cryptimeleon.craco.common.predicate.KeyIndex;
import org.cryptimeleon.craco.enc.CipherText;
import org.cryptimeleon.craco.enc.DecryptionKey;
import org.cryptimeleon.craco.enc.EncryptionKey;
import org.cryptimeleon.craco.enc.SymmetricKey;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.misc.ByteArrayImpl;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.serialization.Representation;

/**
 * A simple implementation of a representable byte array. This byte array can
 * be a plain text or a cipher text or an encryption key and/or a decryption key.
 */
public class ByteArrayImplementation extends ByteArrayImpl
        implements PlainText, CipherText, DecryptionKey, EncryptionKey, SymmetricKey, KeyIndex, CiphertextIndex,
        UniqueByteRepresentable {

    public ByteArrayImplementation(byte[] bytes) {
        super(bytes);
    }

    public ByteArrayImplementation(Representation repr) {
        super(repr);
    }

    /**
     * Creates a new {@code ByteArrayImplementation} instance filled with {@code numberBytes} bytes of randomness
     *
     * @param numberBytes number of random bytes / length of resulting ByteArrayImplementation
     */
    public static ByteArrayImplementation fromRandom(int numberBytes) {
        return new ByteArrayImplementation(RandomGenerator.getRandomBytes(numberBytes));
    }

    @Override
    public ByteArrayImplementation append(ByteArrayImpl a) {
        return new ByteArrayImplementation(super.append(a).getData());
    }

    @Override
    public ByteArrayImplementation substring(int firstIndex, int length) {
        return new ByteArrayImplementation(super.substring(firstIndex, length).getData());
    }

    @Override
    public ByteArrayImplementation xor(ByteArrayImpl a) {
        return new ByteArrayImplementation(super.xor(a).getData());
    }
}
