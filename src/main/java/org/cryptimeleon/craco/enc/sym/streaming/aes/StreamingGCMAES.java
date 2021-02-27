package org.cryptimeleon.craco.enc.sym.streaming.aes;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.math.serialization.Representation;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * An implementation of AES with GCM as the mode of operation.
 * <p>
 * For difference between this and {@link StreamingGCMAESPacketMode}, see the latter's documentation.
 */
public class StreamingGCMAES extends AbstractStreamingSymmetricScheme {

    private static final int initialVectorLength = 96; // in bit

    private static final int tagLength = 128; // in bit, needed for GCM

    private static final String transformation = "AES/GCM/NoPadding";

    public StreamingGCMAES() {
        super(transformation, initialVectorLength);
    }

    public StreamingGCMAES(int keyLength) {
        super(transformation, initialVectorLength, keyLength);
    }

    public StreamingGCMAES(Representation repr) {
        this(repr.bigInt().getInt());
    }

    @Override
    public void initCipher(Cipher cipher, ByteArrayImplementation symmetricKey, int mode)
            throws InvalidAlgorithmParameterException, InvalidKeyException {

        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getData(), "AES");

        // GCM setup
        GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLength, initialVector);
        // initialize the cipher
        cipher.init(mode, keySpec, gcmSpec);
    }
}
