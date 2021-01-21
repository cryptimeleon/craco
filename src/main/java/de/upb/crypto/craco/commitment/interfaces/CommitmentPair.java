package de.upb.crypto.craco.commitment.interfaces;

import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;

/**
 * Result of committing to some value.
 * <p>
 * Contains the commitment itself as well as the value necessary to open the commitment.
 */
public class CommitmentPair implements Representable, UniqueByteRepresentable {

    private final Commitment commitment;
    private final OpenValue openValue;

    public CommitmentPair(Commitment commitment, OpenValue openValue) {
        this.commitment = commitment;
        this.openValue = openValue;
    }

    public Commitment getCommitment() {
        return commitment;
    }

    public OpenValue getOpenValue() {
        return openValue;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(commitment);
        accumulator.escapeAndSeparate(openValue);
        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("com", commitment.getRepresentation());
        repr.put("open", openValue.getRepresentation());

        return repr;
    }
}
