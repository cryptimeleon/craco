package de.upb.crypto.craco.interfaces;

import de.upb.crypto.craco.common.utils.StreamUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An encryption scheme with the added ability to encrypt data from streams.
 * Natural examples are stream- and block ciphers (e.g., AES).
 * <p>
 * Example use: (decrypts a file that is being read)
 * scheme.decrypt(new BufferedInputStream(new FileInputStream(...)), decryptionKey)
 * returns an InputStream where reading supplies exactly the plaintext corresponding
 * to the ciphertext stored in the file.
 * <p>
 * The idea is that encryption/decryption can be used as part of a chain of streams.
 * In the example above: FileInputStream -> BufferedInputStream -> DecryptionInputStream.
 * Similarly, you can chain OutputStreams such that any bytes written to it are encrypted/decrypted
 * and then passed to another OutputStream.
 * <p>
 * Note that the plaintext size and ciphertext size are often NOT the same, hence you cannot
 * expect the chained streams obtained from a StreamingEncryptionScheme to read/write
 * exactly the number of bytes from the chained stream that you read from/write to it.
 * <p>
 * Implementations of this interface should normally be able to do
 * encryption and decryption without loading the whole plaintext/ciphertext into memory.
 *
 * @author Jan
 */
public interface StreamingEncryptionScheme extends EncryptionScheme {

    /**
     * Reads and encrypts the bytes from plainTextIn and writes
     * the ciphertext to cipherTextOut.
     *
     * @throws IOException if any of the streams throw an exception while reading/writing bytes.
     */
    default void encrypt(InputStream plainTextIn, OutputStream cipherTextOut,
                         EncryptionKey publicKey) throws IOException {
        //Wrap plainTextIn with encrypting stream
        InputStream cipherTextIn = encrypt(plainTextIn, publicKey);

        //Copy bytes from stream to stream
        StreamUtil.copy(cipherTextIn, cipherTextOut);
    }

    /**
     * Reads and decrypts a ciphertext from cipherTextIn and writes
     * the resulting plaintext bytes to plainTextOut.
     *
     * @throws IOException if any of the streams throw an exception while reading/writing bytes.
     */
    default void decrypt(InputStream cipherTextIn, OutputStream plainTextOut,
                         DecryptionKey privateKey) throws IOException {
        //Wrap plainTextIn with decrypting stream
        InputStream plainTextIn = decrypt(cipherTextIn, privateKey);

        //Copy bytes from stream to stream
        StreamUtil.copy(plainTextIn, plainTextOut);
    }

    /**
     * Returns an InputStream containing the ciphertext obtained
     * by encrypting the content of in.
     * <p>
     * Note that calling this may already cause some bytes to be read from in.
     *
     * @param in        stream containing the bytes to encrypt
     * @param publicKey the key to encrypt with
     * @return a stream containing the encrypted bytes.
     * @throws IOException
     */
    InputStream encrypt(InputStream in, EncryptionKey publicKey) throws IOException;

    /**
     * Returns an OutputStream that encrypts any bytes written to it
     * and writes the resulting ciphertext to out.
     * <p>
     * Note that calling this may already cause some bytes to be written to out.
     *
     * @param out       the stream to write the ciphertext to.
     * @param publicKey the key to encrypt with.
     * @return a stream that encrypts any input and writes the ciphertext to out.
     * @throws IOException
     */
    OutputStream encrypt(OutputStream out, EncryptionKey publicKey) throws IOException;

    /**
     * Returns an InputStream containing the plaintext obtained
     * by decrypting the content of in.
     * <p>
     * Note that calling this may already cause some bytes to be read from in.
     *
     * @param in         in stream containing the bytes to decrypt
     * @param privateKey the key to decrypt with.
     * @return a stream containing the decrypted bytes.
     * @throws IOException
     */
    InputStream decrypt(InputStream in, DecryptionKey privateKey) throws IOException;

    /**
     * Returns an OutputStream that decrypts any bytes written to it
     * and writes the resulting plaintext to out.
     * <p>
     * Note that calling this may already cause some bytes to be written to out.
     *
     * @param out        the stream to write the plaintext to.
     * @param privateKey the key to decrypt with.
     * @return a stream that decrypts any input and writes the plaintext to out.
     * @throws IOException
     */
    OutputStream decrypt(OutputStream out, DecryptionKey privateKey) throws IOException;
}
