package org.cryptimeleon.craco.commitment;

import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

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
