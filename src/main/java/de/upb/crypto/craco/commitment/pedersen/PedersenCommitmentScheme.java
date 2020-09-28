package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.Commitment;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zn;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;


/**
 * This class provides a java implementation for Pedersen Commitment Scheme. It realizes the general
 * {@link CommitmentScheme} interface and provides a concrete Pedersen Commitment Scheme implementation
 * for (commit, open) methods.
 */
public class PedersenCommitmentScheme implements CommitmentScheme {
    @Represented
    protected Group group;
    @Represented(restorer = "[group]")
    protected List<GroupElement> h; //elements that will carry the committed values
    @Represented(restorer = "group")
    protected GroupElement g; //element that will carry the randomness


    /**
     * Construct a new PedersenCommitmentScheme object providing {@link Representation} object
     *
     * @param repr {@link Representation}
     */
    public PedersenCommitmentScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }


    public PedersenCommitmentScheme(Group group, GroupElement g, List<? extends GroupElement> h) {
        this.group = group;
        this.h = new ArrayList<>();
        this.h.addAll(h);
        this.g = g;
    }

    public PedersenCommitmentScheme(Group group, int numMessages) {
        this.group = group;
        this.h = new ArrayList<>();
        for (int i=0;i<numMessages;i++)
            this.h.add(group.getUniformlyRandomElement());
        this.g = group.getUniformlyRandomNonNeutral();
    }

    /**
     * The committing process accepts an object of type {@link PlainText}. Thus, two concrete objects can be passed
     * as input to this method, namely: {@link RingElementPlainText} (single-message) or
     * {@link MessageBlock} (multi-message).
     *
     * @param plainText object of type {@link MessageBlock} or {@link RingElementPlainText}
     * @return {@link CommitmentPair} the result of commit process
     */
    @Override
    public CommitmentPair commit(PlainText plainText) {
        if (plainText instanceof RingElementPlainText)
            plainText = new MessageBlock(plainText);

        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid PlainText for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;

        if (!(messageBlock.size() == h.size())) {
            throw new UnsupportedOperationException("The message list and parameter list lengths are not compatible!");
        }

        Zn.ZnElement r = group.getUniformlyRandomExponent();
        GroupElement c = getPedersenExpression(r.getInteger(), messageBlock);

        return new CommitmentPair(new PedersenCommitment(c), new PedersenOpenValue(r.getInteger()));
    }

    private GroupElement getPedersenExpression(BigInteger r, MessageBlock msgs) {
        GroupElement expr = g.pow(r);
        for (int i=0;i<msgs.size();i++) {
            expr = expr.op(h.get(i).pow((Zn.ZnElement) ((RingElementPlainText) msgs.get(i)).getRingElement()));
        }
        return expr;
    }

    /**
     * This function performs the opening phase of the committing process. It first verifies that the messages in the
     * open value {@link PedersenOpenValue} conform to the {@link PedersenCommitment} and then checks the
     * equality of the opened messages to the messages provided by the {@link PlainText} input (announced message).
     *
     * @param commitment {@link PedersenCommitment}
     * @param openValue       {@link PedersenOpenValue}
     * @param plainText       {@link PlainText} (announced message)
     * @return boolean value whether the opening process is successful (true) or not (false)
     */
    @Override
    public boolean verify(Commitment commitment, OpenValue openValue, PlainText plainText) {
        if (plainText instanceof RingElementPlainText)
            plainText = new MessageBlock(plainText);

        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid PlainText for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;

        if (messageBlock.size() != h.size() || !messageBlock.stream().allMatch(x -> group.getZn().equals(((Zn.ZnElement) ((RingElementPlainText) x).getRingElement()).getStructure())))
            throw new IllegalArgumentException("Illegal opening value format");

        return getPedersenExpression(((PedersenOpenValue) openValue).getRandomValue(), messageBlock)
                .equals(((PedersenCommitment) commitment).get());
    }

    /**
     * Provides an injective mapping of the byte[] to a {@link MessageBlock}.
     * Alternatively, this method can throw an {@link IllegalArgumentException} if there is no injective
     * {@link PlainText} element of these bytes (i.e. the byte[] is too long).
     *
     * @param bytes byte[] representation of the message to commit
     * @return A {@link MessageBlock} containing the corresponding {@link RingElementPlainText} containing a
     * {@link Zn.ZnElement} in its first element and further padded {@link RingElementPlainText} containing
     * {@link Zn.ZnElement} of value 0.
     */
    @Override
    public MessageBlock mapToPlainText(byte[] bytes) throws IllegalArgumentException {
        RingElementPlainText zero = new RingElementPlainText(group.getZn().getZeroElement());

        RingElementPlainText[] msgBlock = new RingElementPlainText[h.size()];
        msgBlock[0] = new RingElementPlainText(group.getZn().injectiveValueOf(bytes));
        for (int i = 1; i < msgBlock.length; i++) {
            msgBlock[i] = zero;
        }

        return new MessageBlock(msgBlock);
    }

    @Override
    public PedersenCommitment getCommitment(Representation repr) {
        return new PedersenCommitment(group.getElement(repr));
    }

    @Override
    public PedersenOpenValue getOpenValue(Representation repr) {
        return new PedersenOpenValue(repr);
    }

    /**
     * Returns a representation of the object of type {@link PedersenCommitmentScheme} .
     *
     * @return {@link Representation}
     */
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

