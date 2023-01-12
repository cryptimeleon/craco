package org.cryptimeleon.craco.commitment.pedersen;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

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
    public MessageBlock mapToPlaintext(byte[] bytes) throws IllegalArgumentException {
        //Result will be a vector (zp.injectiveValueOf(bytes), 0, ..., 0)
        return new RingElementVector(group.getZn().injectiveValueOf(bytes)).pad(group.getZn().getZeroElement(), h.length())
                .map(RingElementPlainText::new, MessageBlock::new);
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (group.size().bitLength() - 1) / 8;
    }

    @Override
    public PedersenCommitment restoreCommitment(Representation repr) {
        return new PedersenCommitment(group.restoreElement(repr));
    }

    @Override
    public PedersenOpenValue restoreOpenValue(Representation repr) {
        return new PedersenOpenValue(group.getZn().restoreElement(repr));
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

