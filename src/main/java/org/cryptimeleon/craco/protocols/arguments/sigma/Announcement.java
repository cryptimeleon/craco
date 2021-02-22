package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

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
