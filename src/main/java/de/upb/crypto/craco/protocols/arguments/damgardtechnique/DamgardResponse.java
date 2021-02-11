package de.upb.crypto.craco.protocols.arguments.damgardtechnique;

import de.upb.crypto.craco.commitment.OpenValue;
import de.upb.crypto.craco.protocols.arguments.sigma.Announcement;
import de.upb.crypto.craco.protocols.arguments.sigma.Response;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

/**
 * The {@code DamgardResponse} is used in Damgard's Technique. It consists of the commitment of an announcement, the
 * verify-value of the announcement and the original announcement.
 */
class DamgardResponse implements Response {

    private final Response innerResponse;
    private final Announcement innerAnnouncement;
    private final Representation compressedTranscript;
    private final OpenValue openValue;

    /**
     * Constructor for a {@code DamgardResponse}.
     *
     * @param innerResponse response of the original protocol
     * @param innerAnnouncement uncommitted, original announcement of inner protocol
     * @param openValue openvalue for committed announcement
     */
    public DamgardResponse(Response innerResponse, Announcement innerAnnouncement, OpenValue openValue,
                           Representation compressedTranscript) {
        this.innerResponse = innerResponse;
        this.innerAnnouncement = innerAnnouncement;
        this.openValue = openValue;
        this.compressedTranscript = compressedTranscript;
    }

    public Response getInnerResponse() {
        return innerResponse;
    }

    public Announcement getInnerAnnouncement() {
        return innerAnnouncement;
    }

    public OpenValue getOpenValue() {
        return openValue;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("compressedTranscript", compressedTranscript);
        repr.put("openValue", openValue.getRepresentation());
        return repr; //restorer code in DamgardTechnique
    }


    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.escapeAndSeparate(innerResponse);
        byteAccumulator.escapeAndSeparate(innerAnnouncement);
        byteAccumulator.escapeAndAppend(openValue);
        return byteAccumulator;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DamgardResponse that = (DamgardResponse) o;
        return innerResponse.equals(that.innerResponse) && innerAnnouncement.equals(that.innerAnnouncement) && openValue.equals(that.openValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(innerResponse, innerAnnouncement, openValue);
    }
}
