package org.cryptimeleon.craco.protocols.arguments.sigma;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.cartesian.Vector;

import java.util.List;

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

    public class AnnouncementVector extends Vector<Announcement> implements Announcement {

        public AnnouncementVector(Announcement... announcements) {
            super(announcements);
        }

        public AnnouncementVector(List<? extends Announcement> announcements) {
            super(announcements);
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            forEach(accumulator::escapeAndSeparate);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return new ListRepresentation(map(Representable::getRepresentation));
        }
    }

}
