package de.upb.crypto.craco.common.utils;

/**
 * Byte array queue. Can add bytes to end of queue and remove bytes at front.
 *
 *
 */
public final class ByteArrayQueue {
    /**
     * Content of the queue.
     */
    private byte[] data;

    /**
     * Point in array where data starts.
     */
    private int start;

    /**
     * Amount of data stored.
     */
    private int length;

    /**
     * Creates an empty queue.
     */
    public ByteArrayQueue() {
        data = new byte[0];
        start = 0;
        length = 0;
    }

    /**
     * Creates a queue from the given byte array.
     *
     * @param content data which will be stored in the queue
     */
    public ByteArrayQueue(final byte[] content) {
        data = new byte[content.length];
        System.arraycopy(content, 0, data, 0, content.length);
        start = 0;
        length = content.length;
    }

    /**
     * Creates an empty queue with pre-allocated space.
     *
     * @param initialSize size of pre-allocated space
     */
    public ByteArrayQueue(final int initialSize) {
        data = new byte[initialSize];
        start = 0;
        length = 0;
    }

    /**
     * Returns the number of entries in this queue.
     * Does not take into account empty pre-allocated space.
     *
     * @return number of bytes in this queue
     */
    public int size() {
        return length;
    }

    /**
     * Reinitializes this queue to be empty.
     */
    public void reset() {
        data = new byte[0];
        start = 0;
        length = 0;
    }

    /**
     * Removes the given amount of bytes from the head of the queue.
     *
     * @param count number of bytes to remove
     * @return removed bytes
     */
    public byte[] remove(final int count) {
        byte[] result = new byte[count];
        remove(result, 0, count);
        return result;
    }

    /**
     * Removes all stored bytes.
     *
     * @return all stored bytes
     */
    public byte[] remove() {
        return remove(size());
    }

    /**
     * Removes and returns the bytes from the head of the queue until a
     * separation symbol is found. The symbol is also removed, but not returned.
     *
     * @param separationSymbol the separation symbol
     * @return the removed bytes until the separation symbol (exclusive), or null if symbol not found
     */
    public byte[] removeUntil(final byte separationSymbol) {
        int counter = start;
        for (; counter < start + length; counter++) {
            if (data[counter] == separationSymbol) {
                break;
            }
        }
        if (counter == start + length) {
            return null;
        } else {
            byte[] result = remove(counter - start);
            removeByte();
            return result;
        }
    }

    /**
     * Removes and returns the bytes from the tail of the queue until a
     * separation symbol is found. The symbol is also removed, but not returned.
     *
     * @param separationSymbol the separation symbol
     * @return the removed bytes until the separation symbol (exclusive), or null if symbol not found
     */
    public byte[] removeFromTailUntil(final byte separationSymbol) {
        int counter = length - 1;
        for (; counter > start; counter--) {
            if (data[counter] == separationSymbol) {
                break;
            }
        }
        if (counter == start) {
            return null;
        } else {
            byte[] result = removeFromTail(length - 1 - counter);
            removeByteFromTail();
            return result;
        }
    }


    /**
     * Removes a single byte from the head of the queue.
     *
     * @return the removed byte
     */
    public byte removeByte() {
        byte result = data[start];
        start++;
        length--;
        return result;
    }

    /**
     * Removes a single byte from the tail of the queue.
     *
     * @return the removed byte
     */
    public byte removeByteFromTail() {
        byte result = data[length];
        length--;
        return result;
    }

    /**
     * Removes bytes from the tails of the queue.
     *
     * @param count number of bytes to remove
     * @return the removed bytes
     */
    public byte[] removeFromTail(final int count) {
        byte[] result = new byte[count];
        remove(result, count);
        return result;
    }

    /**
     * Removes bytes from the head of the queue and stores them in the given array.
     *
     * @param target the array where the removed bytes should be stored
     * @param count  the number of bytes to remove
     * @throws IllegalArgumentException if this queue does not contain at least {@code count} entries
     */
    public void remove(final byte[] target, final int count) {
        if (start > count) {
            throw new IllegalArgumentException("Trying to remove " + count
                    + " bytes, but queue only has " + length + " bytes");
        }
        System.arraycopy(data, length - count, target, 0, count);
        length -= count;
    }

    /**
     * Removes bytes from the head of the queue and stores them in the given array.
     *
     * @param target the array where the removed bytes should be stored
     * @param offset the offset that species where to start writing into {@code target}
     * @param count  number ob bytes to remove
     * @throws IllegalArgumentException if this queue does not contain at least {@code count} entries
     */
    public void remove(final byte[] target, final int offset, final int count) {
        if (length < count) {
            throw new IllegalArgumentException("Trying to remove " + count
                    + " bytes, but queue only has " + length + " bytes");
        }
        System.arraycopy(data, start, target, offset, count);
        start += count;
        length -= count;
    }

    /**
     * Removes bytes from the head of the queue and stores them in the given array (as many bytes as fit).
     *
     * @param target removed bytes are inserted here
     * @throws IllegalArgumentException if this queue does not contain at least {@code target.length} entries
     */
    public void remove(final byte[] target) {
        remove(target, 0, target.length);
    }

    /**
     * Compacts the underlying storage array by de-allocating any empty space at the end of the underlying array.
     */
    public void compact() {
        if (start == 0 && data.length == length) {
            return;
        }
        byte[] tmp = new byte[length];
        System.arraycopy(data, start, tmp, 0, length);
        data = tmp;
        start = 0;
    }

    /**
     * Resize the underlying storage array to the given new length.
     *
     * @param newLength the new size of the underlying array
     */
    private void resize(final int newLength) {
        if (newLength == length) {
            return;
        }
        compact();
        byte[] tmp = new byte[newLength];
        System.arraycopy(data, 0, tmp, 0, length);
        data = tmp;
    }

    /**
     * Appends {@code inputLen} bytes from {@code array} starting at offset {@code inputOffset} to this queue.
     *
     * @param array       the bytes to add
     * @param inputOffset the offset in {@code array} to start appending bytes from
     * @param inputLen    the number of bytes to append
     */
    public void append(final byte[] array, final int inputOffset, final int inputLen) {
        if (length + inputLen + start > data.length) {
            resize(length + inputLen);
        }
        System.arraycopy(array, inputOffset, data, start + length, inputLen);
        length += inputLen;
    }

    /**
     * Append all bytes from {@code array} to this queue.
     *
     * @param array the bytes to add
     */
    public void append(final byte[] array) {
        append(array, 0, array.length);
    }

    /**
     * Appends the given byte to this queue.
     *
     * @param data the byte to add
     */
    public void append(final byte data) {
        append(new byte[]{data});
    }
}
