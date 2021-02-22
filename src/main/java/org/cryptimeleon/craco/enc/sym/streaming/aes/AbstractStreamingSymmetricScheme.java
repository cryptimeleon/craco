package org.cryptimeleon.craco.enc.sym.streaming.aes;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.utils.StreamUtil;
import org.cryptimeleon.craco.enc.*;
import org.cryptimeleon.craco.enc.exceptions.BadIVException;
import org.cryptimeleon.craco.enc.exceptions.DecryptionFailedException;
import org.cryptimeleon.craco.enc.exceptions.EncryptionFailedException;
import org.cryptimeleon.craco.enc.exceptions.IllegalKeyException;
import org.cryptimeleon.math.random.RandomGenerator;
import org.cryptimeleon.math.serialization.BigIntegerRepresentation;
import org.cryptimeleon.math.serialization.Representation;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

abstract class AbstractStreamingSymmetricScheme implements StreamingEncryptionScheme {

    private static final String INVALID_CT = "Not a valid cipher text for this scheme";

    private static final String INVALID_PT = "Not a valid plain text for this scheme";

    private static final String IO_IV = "Unable to read the IV from stream";

    private static final String INVALID_SYMMETRIC_KEY = "Not a valid symmetric key for this scheme";

    private static String ENC_INVALID_TRANSFORMATION = "The encryption failed because the used transformation "
            + " is invalid.";

    private static String UNQUALIFIED_KEY_LENGTH = "The given key-length is not valid for this AES instance";

    private static String ENC_INVALID_KEY = "The encryption failed because the used key is invalid.";

    private static String DEC_INVALID_TRANSFORMATION = "The decryption failed because the used transformation "
            + " is invalid.";

    private static String DEC_INVALID_KEY = "The decryption failed because the used key is invalid.";

    //////////////////////////////////////////////////////////////////////////////////////////////

    private final int symmetricKeyLength; // in bit

    private final int initialVectorLength; // in bit

    protected byte[] initialVector;

    private String transformation;

    public AbstractStreamingSymmetricScheme(String transformation, int initialVectorLength) {
        this(transformation, initialVectorLength, 128);
    }

    public AbstractStreamingSymmetricScheme(String transformation, int initialVectorLength, int symmetricKeyLength) {
        this.transformation = transformation;
        this.initialVectorLength = initialVectorLength;
        initialVector = new byte[initialVectorLength / 8];
        this.symmetricKeyLength = symmetricKeyLength;
    }

    public abstract void initCipher(Cipher cipher, ByteArrayImplementation symmetricKey, int mode)
            throws InvalidAlgorithmParameterException, InvalidKeyException;

    @Override
    public InputStream encrypt(InputStream in, EncryptionKey publicKey) throws IOException {
        if (!(publicKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_SYMMETRIC_KEY);

        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) publicKey;
        symmetricKey = updateKeyToLength(symmetricKey, symmetricKeyLength);
        createRandomIV();
        try {
            ByteArrayInputStream ivStream = new ByteArrayInputStream(initialVector);

            Cipher cipher = Cipher.getInstance(transformation);
            // Get the cipher
            initCipher(cipher, symmetricKey, Cipher.ENCRYPT_MODE);

            // return a stream that concatenates IV || ciphertext
            @SuppressWarnings("resource")
            CipherInputStream cis = new CipherInputStream(in, cipher);
            return new SequenceInputStream(ivStream, cis);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new EncryptionFailedException(e, ENC_INVALID_TRANSFORMATION);
        } catch (InvalidKeyException e) {
            throw new EncryptionFailedException(e, ENC_INVALID_KEY);
        }
    }

    @Override
    public InputStream decrypt(InputStream in, DecryptionKey privateKey) throws IOException {
        if (!(privateKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_SYMMETRIC_KEY);
        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) privateKey;
        symmetricKey = updateKeyToLength(symmetricKey, symmetricKeyLength);
        try {
            // Try reading the IV from the stream.
            int amount = in.read(initialVector, 0, initialVectorLength / 8);
            // check if the correct amount of bytes were read
            if (amount != initialVectorLength / 8)
                throw new DecryptionFailedException(IO_IV, new BadIVException());
            // Get the cipher
            Cipher cipher = Cipher.getInstance(transformation);
            // Get the cipher
            initCipher(cipher, symmetricKey, Cipher.DECRYPT_MODE);

            return new CipherInputStream(in, cipher);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new DecryptionFailedException(DEC_INVALID_TRANSFORMATION, e);
        } catch (InvalidKeyException e) {
            throw new DecryptionFailedException(DEC_INVALID_KEY, e);
        }
    }

    protected static ByteArrayImplementation updateKeyToLength(ByteArrayImplementation symmetricKey,
                                                               int symmetricKeyLength) {
        if (symmetricKey.length() * 8 == symmetricKeyLength)
            return symmetricKey;
        if (symmetricKey.length() * 8 >= symmetricKeyLength) {
            byte[] keyData = new byte[symmetricKeyLength / 8];
            System.arraycopy(symmetricKey.getData(), 0, keyData, 0, symmetricKeyLength / 8);
            ByteArrayImplementation updatedSymmetricKey = new ByteArrayImplementation(keyData);
            return updatedSymmetricKey;
        } else {
            throw new IllegalKeyException(UNQUALIFIED_KEY_LENGTH);
        }

    }

    @Override
    public OutputStream createEncryptor(OutputStream out, EncryptionKey publicKey) throws IOException {
        if (!(publicKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_SYMMETRIC_KEY);
        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) publicKey;
        symmetricKey = updateKeyToLength(symmetricKey, symmetricKeyLength);
        createRandomIV();
        out.write(initialVector);
        try {
            // Get the cipher
            Cipher cipher = Cipher.getInstance(transformation);
            // Get the cipher
            initCipher(cipher, symmetricKey, Cipher.ENCRYPT_MODE);

            return new CipherOutputStream(out, cipher);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new EncryptionFailedException(e, ENC_INVALID_TRANSFORMATION);
        } catch (InvalidKeyException e) {
            throw new EncryptionFailedException(e, ENC_INVALID_KEY);
        }
    }

    @Override
    public OutputStream createDecryptor(OutputStream out, final DecryptionKey privateKey) throws IOException {
        if (!(privateKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_SYMMETRIC_KEY);

        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) privateKey;
        symmetricKey = updateKeyToLength(symmetricKey, symmetricKeyLength);
        return new StreamingOutputstream(symmetricKey, out);
    }

    @Override
    public void encrypt(InputStream plainTextIn, OutputStream cipherTextOut, EncryptionKey publicKey)
            throws IOException {
        // check for a valid key
        if (!(publicKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_SYMMETRIC_KEY);
        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) publicKey;
        symmetricKey = updateKeyToLength(symmetricKey, symmetricKeyLength);
        // randomize the IV
        createRandomIV();
        // write the IV into the stream
        cipherTextOut.write(initialVector);
        streamHelper(plainTextIn, cipherTextOut, symmetricKey, Cipher.ENCRYPT_MODE);
    }

    @Override
    public void decrypt(InputStream cipherTextIn, OutputStream plainTextOut, DecryptionKey privateKey)
            throws IOException {
        // check for a valid key
        if (!(privateKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_SYMMETRIC_KEY);
        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) privateKey;
        symmetricKey = updateKeyToLength(symmetricKey, symmetricKeyLength);
        // try to read the IV from the stream
        int amount = cipherTextIn.read(initialVector, 0, initialVectorLength / 8);
        // check if the correct amount of bytes were read
        if (amount != initialVectorLength / 8)
            throw new DecryptionFailedException(IO_IV, new BadIVException());
        // start the decryption process
        streamHelper(cipherTextIn, plainTextOut, symmetricKey, Cipher.DECRYPT_MODE);
    }

    @Override
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_PT);

        ByteArrayImplementation pt = (ByteArrayImplementation) plainText;

        ByteArrayInputStream plainBytesIn = new ByteArrayInputStream(pt.getData());
        InputStream plainIn = new BufferedInputStream(plainBytesIn);

        ByteArrayOutputStream cipherBytesOut = new ByteArrayOutputStream();
        OutputStream cipherOut = new BufferedOutputStream(cipherBytesOut);
        try {
            this.encrypt(plainIn, cipherOut, publicKey);
            plainIn.close();
            cipherOut.flush();
            cipherOut.close();
        } catch (IOException e) {
            throw new EncryptionFailedException(e, e.getLocalizedMessage());
        }
        return new ByteArrayImplementation(cipherBytesOut.toByteArray());
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_CT);

        ByteArrayImplementation ct = (ByteArrayImplementation) cipherText;

        ByteArrayInputStream cipherBytesIn = new ByteArrayInputStream(ct.getData());
        InputStream cipherIn = new BufferedInputStream(cipherBytesIn);

        ByteArrayOutputStream plainBytesOut = new ByteArrayOutputStream();
        OutputStream plainOut = new BufferedOutputStream(plainBytesOut);
        try {
            this.decrypt(cipherIn, plainOut, privateKey);
            cipherIn.close();
            plainOut.flush();
            plainOut.close();

        } catch (IOException e) {
            throw new DecryptionFailedException(e, e.getLocalizedMessage());
        }
        return new ByteArrayImplementation(plainBytesOut.toByteArray());
    }

    private void streamHelper(InputStream inputStream, OutputStream outputStream, SymmetricKey key, final int mode)
            throws IOException {
        if (!(key instanceof ByteArrayImplementation))
            throw new IllegalArgumentException(INVALID_SYMMETRIC_KEY);
        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) key;

        // this follows the cipherStreaming tutorial at
        // http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
        CipherInputStream cipherIn = null;
        PipedInputStream pipedIn = null;
        PipedOutputStream pipedOut = null;
        try {
            // Get the cipher
            // Get the cipher
            Cipher cipher = Cipher.getInstance(transformation);
            // Get the cipher
            initCipher(cipher, symmetricKey, mode);

            // read the data from the input stream and write them
            // into the PipedOutputstream
            // which is connected to the cipher
            pipedIn = new PipedInputStream();
            pipedOut = new PipedOutputStream();
            pipedOut.connect(pipedIn);
            StreamUtil.copyAsync(inputStream, pipedOut);
            // generate a CipherInputStream from the given piped input
            // stream and the specified cipher
            cipherIn = new CipherInputStream(pipedIn, cipher);
            // read so many bytes until we get a -1 as length value which means
            // that we should stop
            byte[] readByte = new byte[8];
            int length = cipherIn.read(readByte);
            while (length != -1) {
                outputStream.write(readByte, 0, length);
                length = cipherIn.read(readByte);
            }

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            if (mode == Cipher.ENCRYPT_MODE)
                throw new EncryptionFailedException(e, ENC_INVALID_TRANSFORMATION);
            else
                throw new DecryptionFailedException(DEC_INVALID_TRANSFORMATION, e);
        } catch (InvalidKeyException e) {
            if (mode == Cipher.DECRYPT_MODE)
                throw new DecryptionFailedException(DEC_INVALID_KEY, e);
            else
                throw new EncryptionFailedException(e, ENC_INVALID_KEY);

        } finally {
            if (cipherIn != null)
                cipherIn.close();
            if (pipedIn != null)
                pipedIn.close();
            if (pipedOut != null)
                pipedOut.close();
        }
    }

    private void createRandomIV() {
        initialVector = RandomGenerator.getRandomBytes(initialVectorLength / 8);
    }

    /**
     * Generates a symmetric key, which is a random key with a specified length.
     * The key is represented in a byte array.
     *
     * @return the representable symmetric key
     */
    public SymmetricKey generateSymmetricKey() {
        return new ByteArrayImplementation(RandomGenerator.getRandomBytes(symmetricKeyLength / 8));
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public Representation getRepresentation() {
        return new BigIntegerRepresentation(symmetricKeyLength);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(initialVector);
        result = prime * result + ((transformation == null) ? 0 : transformation.hashCode());
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
        AbstractStreamingSymmetricScheme other = (AbstractStreamingSymmetricScheme) obj;
        if (!Arrays.equals(initialVector, other.initialVector))
            return false;
        if (transformation == null) {
            if (other.transformation != null)
                return false;
        } else if (!transformation.equals(other.transformation))
            return false;
        return true;
    }

    class StreamingOutputstream extends SymmetricOutputstream {

        private ByteArrayImplementation symmetricKey;

        public StreamingOutputstream(ByteArrayImplementation symmetricKey, OutputStream out) {
            super(out, initialVectorLength);
            this.symmetricKey = symmetricKey;

        }

        @Override
        protected void setupOutputStream() {
            try {
                // Get the cipher
                Cipher cipher = Cipher.getInstance(transformation);
                // Get the cipher
                initCipher(cipher, symmetricKey, Cipher.DECRYPT_MODE);

                decryptedOut = new CipherOutputStream(out, cipher);
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                throw new DecryptionFailedException(DEC_INVALID_TRANSFORMATION, e);
            } catch (InvalidKeyException e) {
                throw new DecryptionFailedException(DEC_INVALID_KEY, e);
            }
        }

        @Override
        protected void setIV(int index, byte b) {
            initialVector[index] = b;
        }
    }
}
