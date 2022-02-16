package org.cryptimeleon.craco.commitment.trapdoorcommitment;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;

/**
 * Holds a commitment and a corresponding {@link EquivocationKey}
 * */
public class TrapdoorCommitmentPair implements Representable, UniqueByteRepresentable {

    private final Commitment commitment;

    private final EquivocationKey equivocationKey;

    public TrapdoorCommitmentPair(Commitment commitment, EquivocationKey equivocationKey) {
        this.commitment = commitment;
        this.equivocationKey = equivocationKey;
    }

    public Commitment getCommitment() {
        return commitment;
    }

    public EquivocationKey getEquivocationKey() {
        return equivocationKey;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        accumulator.escapeAndSeparate(commitment);
        accumulator.escapeAndSeparate(equivocationKey);
        return accumulator;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("com", commitment.getRepresentation());
        repr.put("ek", equivocationKey.getRepresentation());

        return repr;
    }

}
