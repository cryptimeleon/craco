package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class PedersenCommitmentValue implements CommitmentValue {

    @Represented
    private Group group;

    @Represented(structure = "group", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement commitmentElement;

    public PedersenCommitmentValue(GroupElement commitmentElement) {
        this.commitmentElement = commitmentElement;
        this.group = commitmentElement.getStructure();
    }

    public PedersenCommitmentValue(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public GroupElement getCommitmentElement() {
        return commitmentElement;
    }

    public void setCommitmentElement(GroupElement commitmentElement) {
        this.commitmentElement = commitmentElement;
    }


    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        return commitmentElement.updateAccumulator(byteAccumulator);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PedersenCommitmentValue that = (PedersenCommitmentValue) o;
        return Objects.equals(group, that.group) &&
                Objects.equals(commitmentElement, that.commitmentElement);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group, commitmentElement);
    }
}
