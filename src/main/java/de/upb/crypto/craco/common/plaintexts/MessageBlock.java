package de.upb.crypto.craco.common.plaintexts;

import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.cartesian.Vector;

import java.util.List;
import java.util.function.Function;

/**
 * A list of plaintext messages for use with multi-message schemes.
 */
public class MessageBlock extends Vector<PlainText> implements PlainText {

    public MessageBlock(PlainText... messages) {
        super(messages);
    }

    public MessageBlock(List<? extends PlainText> messages) {
        super(messages);
    }

    public MessageBlock(Vector<? extends PlainText> messages) {
        super(messages);
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
        this(Vector.generatePlain(i -> messageRestorer.apply(repr.list().get(i)), repr.list().size()));
    }

    @Override
    public Representation getRepresentation() {
        return new ListRepresentation(map(PlainText::getRepresentation).toList());
    }

    @Override
    public String toString() {
        return "MessageBlock "+super.toString();
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        forEach(accumulator::escapeAndSeparate);
        return accumulator;
    }
}
