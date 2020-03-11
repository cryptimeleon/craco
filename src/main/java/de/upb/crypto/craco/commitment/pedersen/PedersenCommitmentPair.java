package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Objects;

public class PedersenCommitmentPair implements CommitmentPair {
    @UniqueByteRepresented
    @Represented
    private PedersenCommitmentValue commitmentValue;

    @UniqueByteRepresented
    @Represented
    private PedersenOpenValue openValue;

    public PedersenCommitmentPair(PedersenCommitmentValue commitmentValue, PedersenOpenValue openValue) {
        this.commitmentValue = commitmentValue;
        this.openValue = openValue;
    }

    public PedersenCommitmentPair(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public PedersenCommitmentValue getCommitmentValue() {
        return commitmentValue;
    }

    @Override
    public PedersenOpenValue getOpenValue() {
        return openValue;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        return AnnotatedUbrUtil.autoAccumulate(byteAccumulator, this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PedersenCommitmentPair that = (PedersenCommitmentPair) o;
        return Objects.equals(commitmentValue, that.commitmentValue) &&
                Objects.equals(openValue, that.openValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commitmentValue, openValue);
    }
}
