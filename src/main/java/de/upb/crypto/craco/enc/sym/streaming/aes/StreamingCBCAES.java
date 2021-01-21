package de.upb.crypto.craco.enc.sym.streaming.aes;

import de.upb.crypto.math.serialization.Representation;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * An implementation of AES with CBC as the mode of operation.
 */
public class StreamingCBCAES extends AbstractStreamingSymmetricScheme {

    private final static int initialVectorLength = 128; // in bit

    private final static String transformation = "AES/CBC/PKCS5Padding";

    public StreamingCBCAES() {
        super(transformation, initialVectorLength);
    }

    public StreamingCBCAES(int keyLength) {
        super(transformation, initialVectorLength, keyLength);
    }

    public StreamingCBCAES(Representation repr) {
        this(repr.bigInt().getInt());
    }

    @Override
    public void initCipher(Cipher cipher, ByteArrayImplementation symmetricKey, int mode)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getData(), "AES");
        cipher.init(mode, keySpec, new IvParameterSpec(initialVector));
    }
}
