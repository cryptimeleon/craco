package de.upb.crypto.craco.enc.sym.streaming.aes;

import de.upb.crypto.craco.common.de.upb.crypto.craco.interfaces.*;
import de.upb.crypto.math.random.RandomGenerator;
import de.upb.crypto.math.serialization.BigIntegerRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * An implementation of AES with GCM as the mode of operation. The difference
 * between this class and {@link StreamingGCMAES} is that the plain text is
 * split up in packets of a well defined size and each of these packets is
 * encrypted with their own IV rather than encrypting the plaintext at once.
 * This reduces the memory overhead that the GCM implementation has. Each plain
 * text is always stored internally while decrypting because the validation of
 * the GCM tag can only be performed when the whole cipher text is decrypted and
 * no unauthorizated data should be provided beforehand.
 * <p>
 * Another problem that the {@link StreamingGCMAES} implementation has, is that
 * it is not a streaming scheme. You can't write the cipher text in the one
 * stream and read the decrypted ciphertext in the other stream since the
 * decrypted ciphertext will be written when you finished writing your cipher
 * text (and close the stream).
 *
 *
 */
public class StreamingGCMAESPacketMode implements StreamingEncryptionScheme {
    public static final int DEFAULT_PACKET_SIZE = 5 * 1024;

    public static final int DEFAULT_KEY_SIZE = 128;

    private final int symmetricKeyLength; // in bit

    private final int initialVectorLength = 96; // in bit

    private final int tagLength = 128; // in bit, needed for GCM

    private byte[] initialVector = new byte[initialVectorLength / 8];

    private final String transformation = "AES/GCM/PKCS5Padding";
    
    private final int packetSize;

    public StreamingGCMAESPacketMode(Representation repr) {
        packetSize = repr.obj().get("packetSize").bigInt().getInt();
        symmetricKeyLength = repr.obj().get("keySize").bigInt().getInt();
    }

    public StreamingGCMAESPacketMode(int packetSize, int symmetricKeyLength) {
        this.packetSize = packetSize;
        this.symmetricKeyLength = symmetricKeyLength;
    }

    public StreamingGCMAESPacketMode(int packetSize) {
        this(packetSize, DEFAULT_KEY_SIZE);
    }

    public StreamingGCMAESPacketMode() {
        this(DEFAULT_PACKET_SIZE, DEFAULT_KEY_SIZE);
    }

    @Override
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Not a valid plain text for this scheme");

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
            throw new RuntimeException(e);
        }
        return new ByteArrayImplementation(cipherBytesOut.toByteArray());
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Not a valid cipher text for this scheme");

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
            throw new RuntimeException(e);
        }
        return new ByteArrayImplementation(plainBytesOut.toByteArray());
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation toReturn = new ObjectRepresentation();
        toReturn.put("packetSize", new BigIntegerRepresentation(packetSize));
        toReturn.put("keySize", new BigIntegerRepresentation(symmetricKeyLength));
        return toReturn;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns an {@link InputStream} that encrypts the bytes read from the
     * given <code>InputStream in</code>. The stream will always read enough
     * bytes from the underlying stream to encrypt a new packet, buffer it and
     * return bytes from it when read is being called. This stream is optimized
     * for the use of {@link InputStream#read(byte[])} and
     * {@link InputStream#read(byte[], int, int)}.
     */
    @Override
    public InputStream encrypt(InputStream in, EncryptionKey publicKey) throws IOException {
        if (!(publicKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Not a valid symmetric key for this scheme");

        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) publicKey;
        symmetricKey = AbstractStreamingSymmetricScheme.updateKeyToLength(symmetricKey, symmetricKeyLength);

        // set up the scheme
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
            throw new RuntimeException(e1);
        }
        // init the key
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getData(), "AES");

        return new InputStream() {
            /** Used to buffer the data between two read calls */
            byte[] bufferedCipherText;
            /** Amount of currently buffered data */
            int bufferedCipherTextSize = 0;
            /** Offset in the bufferedCipherText */
            int bufferedCipherTextOffset = 0;

            int initialVectorLengthInBytes = initialVectorLength / 8;
            /**
             * Indicates how many bytes are already read, needed for
             * transmitting the IV
             */
            int byteOffset = 0;
            /** The packet round */
            BigInteger packetRound = BigInteger.valueOf(0);
            /** InitalVector as BigInteger */
            BigInteger initV;

            @Override
            public int read() throws IOException {
                if (byteOffset == 0) {
                    // init the IV
                    createRandomIV();
                    initV = new BigInteger(initialVector);
                }
                if (byteOffset < (initialVectorLengthInBytes)) {
                    // the IV was not fully read yet
                    // cast it to an unsigned int
                    byteOffset++;
                    return Byte.toUnsignedInt(initialVector[byteOffset++]);
                } else {
                    // the iv was read
                    if (bufferedCipherTextOffset == bufferedCipherTextSize) {
                        int read = bufferPacket();
                        if (read == -1) {
                            // the underlying stream didnt give us any data
                            return -1;
                        }
                    }
                    // we have data now
                    byte toReturn = bufferedCipherText[bufferedCipherTextOffset];
                    bufferedCipherTextOffset++;
                    // 04.11.2016 mirkoj this causes an integer overflow
                    // byteOffset++;
                    // cast it to an unsigned int
                    return Byte.toUnsignedInt(toReturn);
                }
            }

            /**
             * Writes a new packet in the bufferedCipherText.
             *
             * @return the length of the ciphertext or -1 if the plaintext
             *         inputstream could not provide any data
             */
            public int bufferPacket() {
                try {
                    // we don't have any buffered data
                    // start an encryption run
                    byte[] plainText = new byte[packetSize];
                    int read = in.read(plainText);
                    if (read == -1) {
                        // we couldn't read any plaintext data
                        return -1;
                    }
                    // 16.09 mirkoj : we dont the packet to be filled
                    // up with 0's
                    if (read != packetSize) {
                        byte[] tempPlaintext = new byte[packetSize];
                        System.arraycopy(plainText, 0, tempPlaintext, 0, read);
                        plainText = new byte[read];
                        System.arraycopy(tempPlaintext, 0, plainText, 0, read);
                    }
                    BigInteger initV_i = initV.add(packetRound);
                    // iv_i = iv + i
                    byte[] initialVector_i = initV_i.toByteArray();
                    // GCM iv
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLength, initialVector_i);
                    // reinit the cipher
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
                    // calculate the additional authenticated data
                    byte[] packetRoundBytes = packetRound.toByteArray();
                    byte[] aad = new byte[initialVector.length + packetRoundBytes.length];
                    System.arraycopy(initialVector, 0, aad, 0, initialVector.length);
                    System.arraycopy(packetRoundBytes, 0, aad, initialVector.length, packetRoundBytes.length);
                    // init the cipher with aad before encrypting!
                    cipher.updateAAD(aad);
                    // encrypt
                    bufferedCipherText = cipher.doFinal(plainText);
                    bufferedCipherTextSize = bufferedCipherText.length;
                    bufferedCipherTextOffset = 0;
                    packetRound = packetRound.add(BigInteger.ONE);
                    return bufferedCipherTextSize;
                } catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException
                        | IllegalBlockSizeException | BadPaddingException e) {
                    throw new RuntimeException(e);
                }

            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (byteOffset < initialVectorLengthInBytes) {
                    if (byteOffset == 0) {
                        // init the IV
                        createRandomIV();
                        initV = new BigInteger(initialVector);
                    }
                    int remainingIVBytes = initialVectorLengthInBytes - byteOffset;

                    if (remainingIVBytes < len) {
                        // we can read the rest of the IV

                        System.arraycopy(initialVector, byteOffset, b, off, remainingIVBytes);

                        byteOffset = byteOffset + remainingIVBytes;
                        // IV is finished
                        int read = read(b, off + remainingIVBytes, len - remainingIVBytes);
                        if (read == -1) {
                            return remainingIVBytes;
                        } else {
                            return remainingIVBytes + read;
                        }
                    } else {
                        // write as much of the IV as possible
                        System.arraycopy(initialVector, byteOffset, b, off, len);
                        byteOffset = byteOffset + len;
                        return len;
                    }

                } else {
                    // the IV was written
                    int remainingBytes = bufferedCipherTextSize - bufferedCipherTextOffset;
                    if (remainingBytes < len) {
                        // we go not enough buffered bytes
                        if (remainingBytes > 0) {
                            // write the rest of the buffer
                            System.arraycopy(bufferedCipherText, bufferedCipherTextOffset, b, off, remainingBytes);
                            // 04.11.2016 mirkoj this causes the byteOffset
                            // integer to overflow
                            // byteOffset = byteOffset + remainingBytes;
                            bufferedCipherTextOffset = bufferedCipherTextOffset + remainingBytes;
                        }
                        // encrypt a new package
                        int read = bufferPacket();
                        if (remainingBytes == 0 && read == -1) {
                            // no data available and we didnt write anything
                            return -1;
                        }
                        if (read == -1) {
                            // no new data available but we wrote something
                            return remainingBytes;
                        }
                        return remainingBytes + read(b, off + remainingBytes, len - remainingBytes);

                    } else {
                        // got enough buffered bytes
                        System.arraycopy(bufferedCipherText, bufferedCipherTextOffset, b, off, len);
                        // 04.11.2016 mirkoj this causes the byteOffset integer
                        // overflow
                        // byteOffset = byteOffset + len;
                        bufferedCipherTextOffset = bufferedCipherTextOffset + len;
                        return len;
                    }
                }
            }

        };
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns an {@link OutputStream} that encrypts any bytes that are written
     * into it and write the encrypted bytes into the
     * <code>OutputStream out</code>. The stream will always try to buffer
     * enough bytes to encrypt a packet and write it into
     * the<code>OutputStream out</code>.
     * <p>
     * This stream is optimized for the use of
     * {@link OutputStream#write(byte[])} and
     * {@link OutputStream#write(byte[], int, int)}.
     * <p>
     * {@link OutputStream#flush()} will encrypt the currently buffered data as
     * a packet.
     */
    @Override
    public OutputStream encrypt(OutputStream out, EncryptionKey publicKey) throws IOException {
        if (!(publicKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Not a valid symmetric key for this scheme");
        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) publicKey;
        symmetricKey = AbstractStreamingSymmetricScheme.updateKeyToLength(symmetricKey, symmetricKeyLength);

        createRandomIV();
        out.write(initialVector, 0, initialVector.length);
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getData(), "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        OutputStream toReturn = new OutputStream() {
            // to make sure that we won't write more than packetSize bytes
            int bufferedPlainTextOffset = 0;
            int bufferedPlainTextSize = packetSize;
            byte[] bufferedData = new byte[packetSize];

            BigInteger packetRound = BigInteger.valueOf(0);
            BigInteger initV = new BigInteger(initialVector);

            @Override
            public void write(int b) throws IOException {
                int freeData = bufferedPlainTextSize - bufferedPlainTextOffset;
                if (freeData > 0) {
                    bufferedData[bufferedPlainTextOffset] = (byte) b;
                    bufferedPlainTextOffset++;
                } else {
                    writePacket();
                    write(b);
                }
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                int freeData = bufferedPlainTextSize - bufferedPlainTextOffset;
                if (freeData < len) {
                    // not enough freeData
                    // firstwrite all remaining data in the buffer
                    if (freeData > 0)
                        System.arraycopy(b, off, bufferedData, bufferedPlainTextOffset, freeData);
                    bufferedPlainTextOffset = bufferedPlainTextOffset + freeData;
                    // flush it in the outputstream
                    writePacket();
                    write(b, off + freeData, len - freeData);
                } else {
                    // we won't need another packet
                    System.arraycopy(b, off, bufferedData, bufferedPlainTextOffset, len);
                    bufferedPlainTextOffset = bufferedPlainTextOffset + len;
                }

            }

            @Override
            public void write(byte[] b) throws IOException {
                write(b, 0, b.length);
            }

            @Override
            public void close() throws IOException {
                super.close();
                if (bufferedPlainTextOffset > 0)
                    writePacket();
                out.close();
            }

            @Override
            public void flush() throws IOException {
                super.flush();
                if (bufferedPlainTextOffset > 0)
                    writePacket();
                out.flush();
            }

            private void writePacket() {
                BigInteger initV_i = initV.add(packetRound);
                // iv_i = iv + i
                byte[] initialVector_i = initV_i.toByteArray();
                // GCM iv
                GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLength, initialVector_i);
                // reinit the cipher
                try {
                    // 16.09 mirkoj, fixes that the last package isnt filled up
                    // with 0's
                    if (bufferedPlainTextOffset != bufferedPlainTextSize) {
                        byte[] tempData = new byte[bufferedPlainTextOffset];
                        System.arraycopy(bufferedData, 0, tempData, 0, bufferedPlainTextOffset);
                        bufferedData = new byte[bufferedPlainTextOffset];
                        System.arraycopy(tempData, 0, bufferedData, 0, bufferedPlainTextOffset);
                    }
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

                    // calculate the additional authenticated data
                    byte[] packetRoundBytes = packetRound.toByteArray();
                    byte[] aad = new byte[initialVector.length + packetRoundBytes.length];
                    System.arraycopy(initialVector, 0, aad, 0, initialVector.length);
                    System.arraycopy(packetRoundBytes, 0, aad, initialVector.length, packetRoundBytes.length);
                    // init the cipher with aad before encrypting!
                    cipher.updateAAD(aad);
                    // encrypt
                    byte[] cipherText = cipher.doFinal(bufferedData);
                    out.write(cipherText, 0, cipherText.length);
                    packetRound = packetRound.add(BigInteger.ONE);

                    bufferedData = new byte[packetSize];
                    bufferedPlainTextSize = packetSize;
                    bufferedPlainTextOffset = 0;

                } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
                        | BadPaddingException | IOException e) {
                    throw new RuntimeException(e);
                }
            }

        };
        return toReturn;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns an InputStream that decrypts the encrypted bytes of the
     * InputStream <code>InputStream in</code>. The InpuStream will buffer a
     * packet and decrypt it and then read the bytes out of this packet. This
     * stream is optimized, so the use of {@link InputStream#read(byte[])} and
     * {@link InputStream#read(byte[], int, int)} is advised.
     */
    @Override
    public InputStream decrypt(InputStream in, DecryptionKey privateKey) throws IOException {
        if (!(privateKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Not a valid symmetric key for this scheme");

        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) privateKey;
        symmetricKey = AbstractStreamingSymmetricScheme.updateKeyToLength(symmetricKey, symmetricKeyLength);

        Cipher cipher;

        in.read(initialVector);

        try {
            cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
            throw new RuntimeException(e1);
        }
        // init the key
        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getData(), "AES");

        return new InputStream() {
            /** Used to buffer the data between two read calls */
            byte[] bufferedPlainText;
            /** Amount of currently buffered data */
            int bufferedPlainTextSize = 0;
            /** Offset in the bufferedCipherText */
            int bufferedPlainTextOffset = 0;

            int tagLengthInBytes = tagLength / 8;
            int cipherPacketSize = packetSize + tagLengthInBytes;
            /**
             * Indicates how many bytes are already read, needed for
             * transmitting the IV
             */
            @SuppressWarnings("unused")
            int byteOffset = 0;
            /** The packet round */
            BigInteger packetRound = BigInteger.valueOf(0);
            /** InitalVector as BigInteger */
            BigInteger initV = new BigInteger(initialVector);

            @Override
            public int read() throws IOException {

                // the iv was read
                if (bufferedPlainTextOffset == bufferedPlainTextSize) {
                    int read = bufferPacket();
                    if (read == -1) {
                        // the underlying stream didnt give us any data
                        return -1;
                    }
                }

                // we have data now
                byte toReturn = bufferedPlainText[bufferedPlainTextOffset];
                bufferedPlainTextOffset++;
                //byteOffset++;
                // cast it to an unsigned int
                return Byte.toUnsignedInt(toReturn);
            }

            /**
             * Writes a new packet in the bufferedCipherText.
             *
             * @return the length of the ciphertext or -1 if the plaintext
             *         inputstream could not provide any data
             */
            public int bufferPacket() {
                try {
                    // we don't have any buffered data
                    // start an encryption run
                    byte[] cipherText = new byte[cipherPacketSize];
                    int read = in.read(cipherText);
                    if (read == -1) {
                        // we couldn't read any plaintext data
                        return -1;
                    }
                    // 16.09 mirkoj : we dont want the packet to be filled
                    // up with 0's
                    if (read != packetSize) {
                        byte[] tempPlaintext = new byte[cipherPacketSize];
                        System.arraycopy(cipherText, 0, tempPlaintext, 0, read);
                        cipherText = new byte[read];
                        System.arraycopy(tempPlaintext, 0, cipherText, 0, read);
                    }
                    BigInteger initV_i = initV.add(packetRound);
                    // iv_i = iv + i
                    byte[] initialVector_i = initV_i.toByteArray();
                    // GCM iv
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLength, initialVector_i);
                    // reinit the cipher
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                    // calculate the additional authenticated data
                    byte[] packetRoundBytes = packetRound.toByteArray();
                    byte[] aad = new byte[initialVector.length + packetRoundBytes.length];
                    System.arraycopy(initialVector, 0, aad, 0, initialVector.length);
                    System.arraycopy(packetRoundBytes, 0, aad, initialVector.length, packetRoundBytes.length);
                    // init the cipher with aad before encrypting!
                    cipher.updateAAD(aad);
                    // encrypt
                    bufferedPlainText = cipher.doFinal(cipherText);
                    bufferedPlainTextSize = bufferedPlainText.length;
                    bufferedPlainTextOffset = 0;
                    packetRound = packetRound.add(BigInteger.ONE);
                    return bufferedPlainTextSize;
                } catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException
                        | IllegalBlockSizeException | BadPaddingException e) {
                    throw new RuntimeException(e);
                }

            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {

                // the IV was written
                int remainingBytes = bufferedPlainTextSize - bufferedPlainTextOffset;
                if (remainingBytes < len) {
                    // we got not enough buffered bytes
                    if (remainingBytes > 0) {
                        // write the rest of the buffer
                        System.arraycopy(bufferedPlainText, bufferedPlainTextOffset, b, off, remainingBytes);
                        // 04.11.2016 mirkoj causes an integer overflow
                        // byteOffset = byteOffset + remainingBytes;
                        bufferedPlainTextOffset = bufferedPlainTextOffset + remainingBytes;
                    }
                    // encrypt a new package
                    int read = bufferPacket();
                    if (remainingBytes == 0 && read == -1) {
                        // no data available and we didnt write anything
                        return -1;
                    }
                    if (read == -1) {
                        // no new data available but we wrote something
                        return remainingBytes;
                    }
                    return remainingBytes + read(b, off + remainingBytes, len - remainingBytes);

                } else {
                    // got enough buffered bytes
                    System.arraycopy(bufferedPlainText, bufferedPlainTextOffset, b, off, len);
                    // 04.11.2016 mirkoj causes an integer overflow
                    // byteOffset = byteOffset + len;
                    bufferedPlainTextOffset = bufferedPlainTextOffset + len;
                    return len;
                }

            }

            @Override
            public int read(byte[] b) throws IOException {
                return this.read(b, 0, b.length);
            }
        };
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns an {@link OutputStream} that decrypts any bytes that are written
     * into it and write the decrypted bytes into the
     * <code>OutputStream out</code>. The stream will always try to buffer
     * enough bytes to decrypt a packet and write the decrypted packet into
     * the<code>OutputStream out</code>.
     * <p>
     * This stream is optimized for the use of
     * {@link OutputStream#write(byte[])} and
     * {@link OutputStream#write(byte[], int, int)}.
     * <p>
     * {@link OutputStream#flush()} will decrypt the currently buffered data as
     * a packet.
     */
    @Override
    public OutputStream decrypt(OutputStream out, DecryptionKey privateKey) throws IOException {
        if (!(privateKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Not a valid symmetric key for this scheme");
        // setting up the scheme
        ByteArrayImplementation symmetricKey = (ByteArrayImplementation) privateKey;
        symmetricKey = AbstractStreamingSymmetricScheme.updateKeyToLength(symmetricKey, symmetricKeyLength);

        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey.getData(), "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformation);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
            throw new RuntimeException(e1);
        }

        return new OutputStream() {
            /** Describes how many bytes have been written */
            int byteOffset = 0;

            final int ivLengthInBytes = initialVector.length;
            final int tagLengthInBytes = tagLength / 8;
            final int cipherPacketSize = packetSize + tagLengthInBytes;

            /** Specifies at which position in the buffer we are */
            int bufferedDataOffset = 0;
            byte[] bufferedData = new byte[cipherPacketSize];

            BigInteger packetRound = BigInteger.valueOf(0);
            BigInteger initV;

            @Override
            public void write(int b) throws IOException {
                // receiving the IV
                if (byteOffset < ivLengthInBytes) {
                    initialVector[byteOffset] = (byte) b;
                    // received the last byte of the iv
                    if (byteOffset == ivLengthInBytes - 1) {
                        initV = new BigInteger(initialVector);
                    }
                    // 04.11.2016 mirkoj needed since the counter down below is
                    // disabled
                    byteOffset++;
                } else {
                    bufferedData[bufferedDataOffset] = (byte) b;
                    bufferedDataOffset++;

                    if (bufferedDataOffset == cipherPacketSize) {
                        writePacket();
                    }

                }
                // count the received bytes
                // 04.11.2016 mirkoj causes an integer overflow
                // byteOffset++;
            }

            private void writePacket() {
                BigInteger initV_i = initV.add(packetRound);
                // iv_i = iv + i
                byte[] initialVector_i = initV_i.toByteArray();
                // GCM iv
                GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLength, initialVector_i);
                // reinit the cipher
                try {
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                    // 16.09 mirkoj: We dont want to encrypt a full package
                    // here!
                    if (bufferedData.length != bufferedDataOffset) {
                        byte[] tempCiphertext = new byte[bufferedDataOffset];
                        System.arraycopy(bufferedData, 0, tempCiphertext, 0, bufferedDataOffset);
                        bufferedData = new byte[bufferedDataOffset];
                        System.arraycopy(tempCiphertext, 0, bufferedData, 0, bufferedDataOffset);
                    }
                    // calculate the additional authenticated data
                    byte[] packetRoundBytes = packetRound.toByteArray();
                    byte[] aad = new byte[initialVector.length + packetRoundBytes.length];
                    System.arraycopy(initialVector, 0, aad, 0, initialVector.length);
                    System.arraycopy(packetRoundBytes, 0, aad, initialVector.length, packetRoundBytes.length);
                    // init the cipher with aad before encrypting!
                    cipher.updateAAD(aad);
                    // encrypt
                    byte[] plainText = cipher.doFinal(bufferedData);
                    out.write(plainText, 0, bufferedDataOffset - tagLengthInBytes);

                    bufferedData = new byte[cipherPacketSize];
                    packetRound = packetRound.add(BigInteger.ONE);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
                        | BadPaddingException | IOException e) {
                    throw new RuntimeException(e);
                }
                bufferedDataOffset = 0;
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {

                if (byteOffset < ivLengthInBytes) {
                    int remainingIVBytes = ivLengthInBytes - byteOffset;
                    if (remainingIVBytes < len) {
                        for (int i = off; i < off + remainingIVBytes; i++) {
                            write(b[i]);
                        }
                        write(b, off + remainingIVBytes, len - remainingIVBytes);
                    } else {
                        for (int i = off; i < off + len; i++) {
                            write(b[i]);
                        }
                    }

                } else {
                    int freeData = bufferedData.length - bufferedDataOffset;
                    // more data remaining than needed
                    if (len < freeData) {
                        // we won't need another packet
                        if (len > 0)
                            System.arraycopy(b, off, bufferedData, bufferedDataOffset, len);
                        // 04.11.2016 mirkoj this causes the byteOffset Integer
                        // overflow
                        // byteOffset = byteOffset + len;
                        bufferedDataOffset = bufferedDataOffset + (len);
                    } else {
                        // write the remaining data in the buffer
                        System.arraycopy(b, off, bufferedData, bufferedDataOffset, freeData);
                        bufferedDataOffset = bufferedDataOffset + freeData;
                        // 04.11.2016 mirkoj this causes the byteOffset integer
                        // overflow
                        // byteOffset = byteOffset + freeData;
                        writePacket();
                        write(b, off + freeData, len - freeData);
                    }

                }
            }

            @Override
            public void write(byte[] b) throws IOException {
                write(b, 0, b.length);
            }

            @Override
            public void close() throws IOException {
                super.close();
                if (bufferedDataOffset > 0)
                    writePacket();
                out.close();
            }

            @Override
            public void flush() throws IOException {
                super.flush();
                if (bufferedDataOffset > 0)
                    writePacket();

                out.flush();
            }
        };

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
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(initialVector);
        result = prime * result + initialVectorLength;
        result = prime * result + packetSize;
        result = prime * result + symmetricKeyLength;
        result = prime * result + tagLength;
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
        StreamingGCMAESPacketMode other = (StreamingGCMAESPacketMode) obj;
        if (!Arrays.equals(initialVector, other.initialVector))
            return false;
        if (initialVectorLength != other.initialVectorLength)
            return false;
        if (packetSize != other.packetSize)
            return false;
        if (symmetricKeyLength != other.symmetricKeyLength)
            return false;
        if (tagLength != other.tagLength)
            return false;
        if (transformation == null) {
            if (other.transformation != null)
                return false;
        } else if (!transformation.equals(other.transformation))
            return false;
        return true;
    }

}