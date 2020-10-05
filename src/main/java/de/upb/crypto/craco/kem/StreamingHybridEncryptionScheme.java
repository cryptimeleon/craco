package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.craco.kem.KeyEncapsulationMechanism.KeyAndCiphertext;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.converter.JSONConverter;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Class that supports streaming encryption using a KEM to encapsulate a
 * symmetric key.
 */
public class StreamingHybridEncryptionScheme implements StreamingEncryptionScheme {

    @Represented
    private StreamingEncryptionScheme symmetricScheme;

    @Represented
    private KeyEncapsulationMechanism<SymmetricKey> kem;

    public class HybridCipherText implements CipherText {

        @Represented(restorer = "Scheme")
        private CipherText ciphertext;

        @Represented(restorer = "Kem")
        private CipherText encapsulatedKey;

        public HybridCipherText(CipherText ciphertext, CipherText encapsulatedKey) {
            this.ciphertext = ciphertext;
            this.encapsulatedKey = encapsulatedKey;
        }

        public HybridCipherText(Representation repr, StreamingEncryptionScheme scheme,
                                KeyEncapsulationMechanism<SymmetricKey> kem) {
            new ReprUtil(this).register(scheme, "Scheme").register(kem, "Kem").deserialize(repr);
        }

        @Override
        public Representation getRepresentation() {
            return ReprUtil.serialize(this);
        }

    }

    public StreamingHybridEncryptionScheme(StreamingEncryptionScheme symmetricScheme,
                                           KeyEncapsulationMechanism<SymmetricKey> kem2) {
        this.symmetricScheme = symmetricScheme;
        this.kem = kem2;
    }

    public StreamingHybridEncryptionScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        KeyAndCiphertext<SymmetricKey> keyAndCiphertext = kem.encaps(publicKey);
        return new HybridCipherText(symmetricScheme
                .encrypt(plainText, keyAndCiphertext.key), keyAndCiphertext.encapsulatedKey);
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        SymmetricKey symmetricKey = kem.decaps(((HybridCipherText) cipherText).encapsulatedKey, privateKey);
        return symmetricScheme.decrypt(((HybridCipherText) cipherText).ciphertext, symmetricKey);
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return symmetricScheme.getPlainText(repr);
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new HybridCipherText(repr, symmetricScheme, kem);
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return kem.getEncapsulationKey(repr);
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return kem.getDecapsulationKey(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public InputStream encrypt(InputStream in, EncryptionKey publicKey) throws IOException {
        //Generate symmetric key and encapsulate it
        KeyAndCiphertext<SymmetricKey> keyAndCiphertext = kem.encaps(publicKey);

        //Serialize the encapsulated key
        byte[] encapsulatedKey = new JSONConverter().serialize(keyAndCiphertext.encapsulatedKey.getRepresentation())
                .getBytes(StandardCharsets.UTF_8);

        //Prepare the encapsulated key length as the first four bytes of the ciphertext. That ought to be enough for
        // everybody.
        byte[] keyLenBytes = ByteBuffer.allocate(4).putInt(encapsulatedKey.length).array();

        //Return resulting stream that concatenates: keyLenBytes || encapsulatedKey || ciphertextFromSymmetricScheme
        return new SequenceInputStream(new ByteArrayInputStream(keyLenBytes),
                new SequenceInputStream(new ByteArrayInputStream(encapsulatedKey),
                        symmetricScheme.encrypt(in, keyAndCiphertext.key)));
    }

    @Override
    public OutputStream encrypt(OutputStream out, EncryptionKey publicKey) throws IOException {
        //Generate symmetric key and encapsulate it
        KeyAndCiphertext<SymmetricKey> keyAndCiphertext = kem.encaps(publicKey);

        //Serialize the encapsulated key
        byte[] encapsulatedKey = new JSONConverter().serialize(keyAndCiphertext.encapsulatedKey.getRepresentation())
                .getBytes(StandardCharsets.UTF_8);

        //Prepare the encapsulated key length as the first four bytes of the ciphertext. That ought to be enough for
        // everybody.
        byte[] keyLenBytes = ByteBuffer.allocate(4).putInt(encapsulatedKey.length).array();

        //Write keyLenBytes || encapsulatedKey to stream
        out.write(keyLenBytes);
        out.write(encapsulatedKey);

        //Return resulting stream that symmetrically encrypts any input and writes the ciphertext to out
        return symmetricScheme.encrypt(out, keyAndCiphertext.key);
    }

    @Override
    public InputStream decrypt(InputStream in, DecryptionKey privateKey) throws IOException {
        //Read the first four bytes to retrieve the size of the encapsulated key
        byte[] keyLenBytes = new byte[4];
        int triesLeft = 10;
        for (int i = 0; i < 4; i++) {
            while (in.read(keyLenBytes, i, 1) < 1 && --triesLeft > 0) {
                ;
            }
        }
        if (triesLeft == 0)
            throw new IOException("didn't get keylen data from ciphertext");
        int keyLen = ByteBuffer.wrap(keyLenBytes).getInt();

        //Deserialize the encapsulated key
        byte[] encapsulatedKeyBytes = new byte[keyLen];
        triesLeft = 10;
        for (int i = 0; i < keyLen; i++) {
            while (in.read(encapsulatedKeyBytes, i, 1) < 1 && --triesLeft > 0) {
                ; //TODO: don't read byte by byte...
            }
        }
        if (triesLeft == 0)
            throw new IOException("couldn't read encapulated key from ciphertext");
        CipherText encapsulatedKey =
                kem.getEncapsulatedKey(new JSONConverter().deserialize(new String(encapsulatedKeyBytes)));

        //decaps the encapsulated key
        SymmetricKey symmetricKey = kem.decaps(encapsulatedKey, privateKey);

        //Return a stream where caller can read the decrypted payload
        return symmetricScheme.decrypt(in, symmetricKey);
    }

    @Override
    public OutputStream decrypt(OutputStream out, DecryptionKey privateKey) {
        return new OutputStream() {
            int byteOffset = 0;
            byte[] keyLenBytes = new byte[4];
            int keyLen = 0;
            byte[] encapsulatedKeyBytes = null;
            OutputStream decryptedOut = null;

            @Override
            public void write(int b) throws IOException {
                if (byteOffset < 4) { //we're still getting the keyLen portion of the ciphertext
                    keyLenBytes[byteOffset] = (byte) b;
                    if (byteOffset == 3) {
                        keyLen = ByteBuffer.wrap(keyLenBytes).getInt();
                        encapsulatedKeyBytes = new byte[keyLen];
                    }
                } else if (byteOffset < 4 + keyLen) { //we're still getting encapsulatedKeyBytes
                    encapsulatedKeyBytes[byteOffset - 4] = (byte) b;
                    if (byteOffset == 4 + keyLen - 1) { //last byte of encapsulated key read
                        CipherText encapsulatedKey = kem.getEncapsulatedKey(new JSONConverter()
                                .deserialize(new String(encapsulatedKeyBytes)));

                        //decaps the encapsulated key
                        SymmetricKey symmetricKey = kem.decaps(encapsulatedKey, privateKey);
                        decryptedOut = symmetricScheme.decrypt(out, symmetricKey);
                    }
                } else { //we're done reading the encapsulation part and are now getting the symmetric scheme's
                    // ciphertext
                    decryptedOut.write(b);
                }

                byteOffset++;
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (byteOffset < 4 + keyLen)
                    for (int i = off; i < off + len; i++) {
                        write(b[i]);
                    }
                else
                    decryptedOut.write(b, off, len);
            }

            @Override
            public void write(byte[] b) throws IOException {
                write(b, 0, b.length);
            }

            @Override
            public void flush() throws IOException {
                if (decryptedOut != null)
                    decryptedOut.flush();
            }

            @Override
            public void close() throws IOException {
                if (decryptedOut != null)
                    decryptedOut.close();
                out.close();
            }
        };
    }

    public KeyEncapsulationMechanism<SymmetricKey> getKeyEncapsulationMechanism() {
        return kem;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((kem == null) ? 0 : kem.hashCode());
        result = prime * result + ((symmetricScheme == null) ? 0 : symmetricScheme.hashCode());
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
        StreamingHybridEncryptionScheme other = (StreamingHybridEncryptionScheme) obj;
        return Objects.equals(symmetricScheme, other.symmetricScheme)
                && Objects.equals(kem, other.kem);
    }

}
