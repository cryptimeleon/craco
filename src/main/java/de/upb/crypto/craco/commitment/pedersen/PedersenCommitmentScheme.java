package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.Commitment;
import de.upb.crypto.craco.commitment.CommitmentPair;
import de.upb.crypto.craco.commitment.CommitmentScheme;
import de.upb.crypto.craco.commitment.OpenValue;
import de.upb.crypto.craco.common.plaintexts.MessageBlock;
import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.common.plaintexts.RingElementPlainText;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.cartesian.Vector;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.cartesian.GroupElementVector;
import de.upb.crypto.math.structures.rings.cartesian.RingElementVector;
import de.upb.crypto.math.structures.rings.zn.Zn;

import java.util.Objects;


/**
 * This class provides a java implementation for the Pedersen commitment scheme. It realizes the general
 * {@link CommitmentScheme} interface and provides a concrete Pedersen commitment scheme implementation
 * for (commit, open) methods.
 */
public class PedersenCommitmentScheme implements CommitmentScheme {
    @Represented
    protected Group group;
    @Represented(restorer = "group")
    protected GroupElementVector h; //elements that will carry the committed values
    @Represented(restorer = "group")
    protected GroupElement g; //element that will carry the randomness


    public PedersenCommitmentScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public PedersenCommitmentScheme(Group group, GroupElement g, GroupElementVector h) {
        this.group = group;
        this.h = h;
        this.g = g;
    }

    public PedersenCommitmentScheme(Group group, int numMessages) {
        this.group = group;
        this.h = group.getUniformlyRandomElements(numMessages);
        this.g = group.getUniformlyRandomNonNeutral();
    }

    @Override
    public CommitmentPair commit(PlainText plainText) {
        return commit(plaintextToRingElementVector(plainText));
    }

    public CommitmentPair commit(Zn.ZnElement... valuesToCommit) {
        return commit(new RingElementVector(valuesToCommit));
    }

    public CommitmentPair commit(RingElementVector valuesToCommit) {
        return commit(valuesToCommit, group.getUniformlyRandomExponent());
    }

    public CommitmentPair commit(RingElementVector valuesToCommit, Zn.ZnElement randomness) {
        if (valuesToCommit.length() != h.length()) {
            throw new UnsupportedOperationException("Plaintext must consist of "+h.length()+" ZnElements");
        }
        GroupElement c = h.innerProduct(valuesToCommit).op(g.pow(randomness));

        return new CommitmentPair(new PedersenCommitment(c), new PedersenOpenValue(randomness));
    }

    @Override
    public boolean verify(Commitment commitment, OpenValue openValue, PlainText plainText) {
        return verify(commitment, openValue, plaintextToRingElementVector(plainText));
    }

    public boolean verify(Commitment commitment, OpenValue openValue, RingElementVector committedValues) {
        return commit(committedValues, ((PedersenOpenValue) openValue).getRandomValue()).getCommitment()
                .equals(commitment);
    }

    @Override
    public MessageBlock mapToPlainText(byte[] bytes) throws IllegalArgumentException {
        RingElementPlainText zero = new RingElementPlainText(group.getZn().getZeroElement());
        return new MessageBlock(
                Vector.of(new RingElementPlainText(group.getZn().injectiveValueOf(bytes)))
                        .pad(zero, h.length())
        );
    }

    @Override
    public PedersenCommitment getCommitment(Representation repr) {
        return new PedersenCommitment(group.getElement(repr));
    }

    @Override
    public PedersenOpenValue getOpenValue(Representation repr) {
        return new PedersenOpenValue(group.getZn().getElement(repr));
    }

    private RingElementVector plaintextToRingElementVector(PlainText plainText) {
        if (plainText instanceof RingElementPlainText)
            plainText = new MessageBlock(plainText);

        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid PlainText for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;

        return new RingElementVector(messageBlock.map(m -> ((RingElementPlainText) m ).getRingElement()));
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PedersenCommitmentScheme that = (PedersenCommitmentScheme) o;
        return Objects.equals(group, that.group) &&
                Objects.equals(h, that.h) &&
                Objects.equals(g, that.g);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group, h, g);
    }
}

