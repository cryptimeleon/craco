package org.cryptimeleon.craco.common.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Util methods for I/O streams.
 *
 *
 */
public final class StreamUtil {
    /**
     * hidden constructor.
     */
    private StreamUtil() {

    }

    /**
     * Starts a thread that reads data from the given {@code InputStream} and writes them into the given
     * {@code OutputStream}. This thread closes the output stream when its done.
     *
     * @param readFrom the stream to read the data from
     * @param writeTo  the stream to write the data to
     */
    public static void copyAsync(InputStream readFrom, final OutputStream writeTo) {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] data = new byte[8];
                    int length = readFrom.read(data);
                    while (length != -1) {
                        writeTo.write(data, 0, length);
                        length = readFrom.read(data);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                } finally {

                    try {
                        writeTo.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            }
        });
        t.start();
    }

    /**
     * Copy all bytes from {@code in} to {@code out} using a buffer with the given {@code bufferSize}.
     *
     * @param in the stream to copy bytes from
     * @param out the stream to copy bytes to
     * @param bufferSize the buffer for storing the bytes between reading and writing
     * @throws IOException if something goes wrong during writing/reading
     */
    public static void copy(InputStream in, OutputStream out, int bufferSize) throws IOException {
        byte[] buf = new byte[bufferSize];
        int read = 0;
        while ((read = in.read(buf)) != -1) {
            out.write(buf, 0, read);
        }
    }

    /**
     * Copy all bytes from in to out using a static buffer size of 1024 bytes.
     *
     * @param in the stream to copy bytes from
     * @param out the stream to copy bytes to
     * @throws IOException if something goes wrong during writing/reading
     */
    public static void copy(InputStream in, OutputStream out) throws IOException {
        copy(in, out, 1024);
    }
}
