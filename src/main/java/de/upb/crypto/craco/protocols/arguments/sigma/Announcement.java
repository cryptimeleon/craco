package de.upb.crypto.craco.protocols.arguments.sigma;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

/**
 * A {@link SigmaProtocol}'s first message.
 */
public interface Announcement extends Representable, UniqueByteRepresentable {
    EmptyAnnouncement EMPTY = new EmptyAnnouncement();

    class EmptyAnnouncement implements Announcement {
        private EmptyAnnouncement() {}

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return null;
        }
    }
}
