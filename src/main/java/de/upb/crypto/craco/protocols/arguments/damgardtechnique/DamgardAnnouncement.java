package de.upb.crypto.craco.protocols.arguments.damgardtechnique;

import de.upb.crypto.craco.commitment.Commitment;
import de.upb.crypto.craco.commitment.CommitmentScheme;
import de.upb.crypto.craco.protocols.arguments.sigma.Announcement;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

/**
 * The {@code DamgardAnnouncement} is the commitment of an announcement of the original Sigma-Protocol.
 */
class DamgardAnnouncement implements Announcement {

    @UniqueByteRepresented
    @Represented(restorer = "com")
    private Commitment commitmentValue;

    /**
     * Constructor for {@code DamgardAnnouncement}.
     *
     * @param commitmentValue commitment value for announcements from Damgard's Technique
     */
    public DamgardAnnouncement(Commitment commitmentValue) {
        this.commitmentValue = commitmentValue;
    }

    /**
     * Recreates the {@code DamgardAnnouncement} from the given {@code Representation}.
     *
     * @param representation the representation to restore the announcement from
     * @param commitmentScheme the involved commitment scheme
     */
    public DamgardAnnouncement(Representation representation, CommitmentScheme commitmentScheme) {
        new ReprUtil(this).register(commitmentScheme, "com").deserialize(representation);
    }

    public Commitment getCommitment() {
        return commitmentValue;
    }


    /**
     * Returns a {@code Representation} of this announcement.
     *
     * @return a {@code Representation} or null if the type alone suffices to instantiate an equal object
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    /**
     * Updates the {@code ByteAccumulator} with the bytes from this class.
     * The input to the accumulators update function should be an injective
     * (with respect to a given domain) byte encoding of this object.
     *
     * @param accumulator the given accumulator
     */
    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DamgardAnnouncement that = (DamgardAnnouncement) o;

        return getCommitment() != null ? getCommitment().equals(that.getCommitment()) : that.getCommitment() == null;
    }

    @Override
    public int hashCode() {
        return getCommitment() != null ? getCommitment().hashCode() : 0;
    }
}
