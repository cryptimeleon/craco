package de.upb.crypto.craco.common;

import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

import java.util.*;
import java.util.function.Function;

/**
 * A list of plaintext messages for use with multi-message schemes.
 */
public class MessageBlock implements PlainText, List<PlainText> {

    @UniqueByteRepresented
    private final List<PlainText> messages = new ArrayList<>();

    public MessageBlock() {

    }

    public MessageBlock(PlainText... messages) {
        this(Arrays.asList(messages));
    }

    public MessageBlock(Collection<? extends PlainText> messages) {
        this.messages.addAll(messages);
    }

    /**
     * Reconstructs the message block from its representation.
     * <p>
     * Caller needs to supply a function messageRestorer that is used to
     * restore each message in this block (e.g., {@code repr -> new RingElementPlainText(myRing.getElement(repr)}).
     *
     * @param repr the representation to restore the message block from
     * @param messageRestorer a function that can restore the message representations contained in the message
     *                        block representation
     */
    public MessageBlock(Representation repr, Function<Representation, ? extends PlainText> messageRestorer) {
        repr.list().forEach(r -> messages.add(messageRestorer.apply(r)));
    }

    @Override
    public Representation getRepresentation() {
        ListRepresentation result = new ListRepresentation();
        messages.stream().map(Representable::getRepresentation).forEachOrdered(result::put);
        return result;
    }

    @Override
    public boolean add(PlainText m) {
        return messages.add(m);
    }

    @Override
    public void clear() {
        messages.clear();
    }

    @Override
    public boolean contains(Object o) {
        return messages.contains(o);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return messages.containsAll(c);
    }

    @Override
    public boolean isEmpty() {
        return messages.isEmpty();
    }

    @Override
    public Iterator<PlainText> iterator() {
        return messages.iterator();
    }

    @Override
    public boolean remove(Object o) {
        return messages.remove(o);
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        return messages.removeAll(c);
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        return messages.retainAll(c);
    }

    @Override
    public int size() {
        return messages.size();
    }

    @Override
    public Object[] toArray() {
        return messages.toArray();
    }

    @Override
    public <T2> T2[] toArray(T2[] a) {
        return messages.toArray(a);
    }

    @Override
    public PlainText get(int index) {
        return messages.get(index);
    }

    @Override
    public PlainText remove(int index) {
        return messages.remove(index);
    }

    @Override
    public int indexOf(Object o) {
        return messages.indexOf(o);
    }

    @Override
    public int lastIndexOf(Object o) {
        return messages.lastIndexOf(o);
    }

    @Override
    public boolean addAll(Collection<? extends PlainText> c) {
        return messages.addAll(c);
    }

    @Override
    public boolean addAll(int index, Collection<? extends PlainText> c) {
        return messages.addAll(index, c);
    }

    @Override
    public PlainText set(int index, PlainText element) {
        return messages.set(index, element);
    }

    @Override
    public void add(int index, PlainText element) {
        messages.add(index, element);
    }

    @Override
    public ListIterator<PlainText> listIterator() {
        return messages.listIterator();
    }

    @Override
    public ListIterator<PlainText> listIterator(int index) {
        return messages.listIterator(index);
    }

    @Override
    public List<PlainText> subList(int fromIndex, int toIndex) {
        return messages.subList(fromIndex, toIndex);
    }

    @Override
    public String toString() {
        return "MessageBlock [messages=" + messages + "]";
    }

    @Override
    public int hashCode() {
        return messages.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        MessageBlock other = (MessageBlock) obj;
        return Objects.equals(messages, other.messages);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
