package de.upb.crypto.craco.enc.sym.streaming.aes;

import javax.crypto.CipherOutputStream;
import java.io.IOException;
import java.io.OutputStream;

abstract class SymmetricOutputstream extends OutputStream {

    int byteOffset = 0;

    final int ivLengthInBytes;

    protected CipherOutputStream decryptedOut = null;

    protected OutputStream out;

    public SymmetricOutputstream(OutputStream out, int initialVectorLength) {
        this.out = out;
        this.ivLengthInBytes = initialVectorLength / 8;
    }

    @Override
    public void write(int b) throws IOException {
        // receiving the IV
        if (byteOffset < ivLengthInBytes) {
            setIV(byteOffset, (byte) b);
            if (byteOffset == ivLengthInBytes - 1) {
                // Done receiving the vector
                setupOutputStream();
            }
            // count the received bytes
            byteOffset++;
        } else {
            // got the IV and we can write it into the
            // CipherOutputStream now.
            decryptedOut.write(b);
        }

    }

    protected abstract void setupOutputStream();

    protected abstract void setIV(int index, byte b);

    @Override
    public void write(byte[] b, int off, int len) throws IOException {

        if (byteOffset < ivLengthInBytes)
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

}
