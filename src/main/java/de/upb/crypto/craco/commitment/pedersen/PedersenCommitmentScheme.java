package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.Commitment;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.math.expressions.exponent.ExponentConstantExpr;
import de.upb.crypto.math.expressions.group.GroupElementConstantExpr;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.expressions.group.GroupOpExpr;
import de.upb.crypto.math.expressions.group.GroupPowExpr;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zn;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.List;


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
     * @param representation {@link Representation}
     */
    public PedersenCommitmentScheme(Representation representation) {
        new ReprUtil(this).deserialize(representation);
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
        // Generate r
        Zn zP = group.getZn();
        Zp.ZpElement r = generateR(pp.getP());

        // Compute c
        GroupElement g = pp.getG();
        GroupElementExpression c = new GroupPowExpr(
                g.expr(),
                r.asExponentExpression()
        );

        // Prepare the messages for committing
        Zp.ZpElement[] messagesInZp = new Zp.ZpElement[messageBlock.size()];
        for (int i = 0; i < messagesInZp.length; i++) {
            if (messageBlock.get(i) instanceof RingElementPlainText &&
                    ((RingElementPlainText) messageBlock.get(i)).getRingElement() instanceof Zp.ZpElement) {
                if (!(zP.equals(((RingElementPlainText) messageBlock.get(i)).getRingElement().getStructure()))) {
                    throw new IllegalArgumentException("The given Message m_" + i + "=" + messageBlock.get(i)
                            + " is not from"
                            + " the same ZP Group as given in the public paramter. Group of m_i=Z_"
                            + ((Zp.ZpElement) messageBlock.get(i)).getStructure().size()
                            + ", expected Structure is Z_" + zP.size());
                }
                messagesInZp[i] = (Zp.ZpElement) ((RingElementPlainText) messageBlock.get(i)).getRingElement();
            }
        }
        // Perform Commitment
        Zp.ZpElement mi;
        GroupElement hi;
        for (int i = 0; i < messagesInZp.length; i++) {
            mi = messagesInZp[i];
            hi = pp.getH()[i];
            c = c.opPow(hi.expr(), mi);
        }
        // Construct the commitment object
        PedersenOpenValue openValue = new PedersenOpenValue(messagesInZp, r);
        PedersenCommitment com = new PedersenCommitment(c.evaluate());
        return new CommitmentPair(com, openValue);
    }

    /**
     * This private function opens the commitment ({@link PedersenCommitment}) to a message with a given
     * {@link OpenValue} and returns a {@link Zp.ZpElement}. This is done by checking that the messages in
     * {@link PedersenOpenValue} conforms to the {@link PedersenCommitment}.
     *
     * @param pedersenCommitmentValue {@link PedersenCommitment}
     * @param pedersenOpenValue       {@link PedersenOpenValue}
     * @return Array of opened messages of type {@link Zp.ZpElement} or null if the open failed.
     */
    private Zp.ZpElement[] open(PedersenCommitment pedersenCommitmentValue, PedersenOpenValue pedersenOpenValue) {
        Zp.ZpElement[] messages = pedersenOpenValue.getMessages();
        GroupElement g = pp.getG();
        GroupElementExpression result = new GroupPowExpr(
                g.expr(),
                pedersenOpenValue.getRandomValue().asExponentExpression()
        );
        Zp.ZpElement mi;
        GroupElement hi;
        for (int i = 0; i < messages.length; i++) {
            mi = messages[i];
            hi = pp.getH()[i];
            result = result.opPow(hi.expr(), mi);
        }
        GroupElement c = pedersenCommitmentValue.get();
        return c.equals(result.evaluate()) ? pedersenOpenValue.getMessages() : null;
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

        if (!(commitment instanceof PedersenCommitment) || !(openValue instanceof PedersenOpenValue)) {
            return false;
        }

        Zp.ZpElement[] openedMessages = this.open((PedersenCommitment) commitment, (PedersenOpenValue)
                openValue);

        if (openedMessages == null) {
            return false;
        }

        if (messageBlock.size() != openedMessages.length) {
            return false;
        }

        for (int i = 0; i < messageBlock.size(); i++) {
            Zp.ZpElement examinedMessage = null;
            if ((messageBlock.get(i) instanceof RingElementPlainText &&
                    ((RingElementPlainText) messageBlock.get(i)).getRingElement() instanceof Zp.ZpElement)) {
                examinedMessage = (Zp.ZpElement) ((RingElementPlainText) messageBlock.get(i)).getRingElement();
            }
            if (!(openedMessages[i].equals(examinedMessage))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Provides an injective mapping of the byte[] to a {@link MessageBlock}.
     * Alternatively, this method can throw an {@link IllegalArgumentException} if there is no injective
     * {@link PlainText} element of these bytes (i.e. the byte[] is too long).
     *
     * @param bytes byte[] representation of the message to commit
     * @return A {@link MessageBlock} containing the corresponding {@link RingElementPlainText} containing a
     * {@link Zp.ZpElement} in its first element and further padded {@link RingElementPlainText} containing
     * {@link Zp.ZpElement} of value 0.
     */
    @Override
    public MessageBlock mapToPlainText(byte[] bytes) throws IllegalArgumentException {
        Zp zp = pp.getZp();
        RingElementPlainText zero = new RingElementPlainText(zp.getZeroElement());
        int messageBlockLength = pp.getH().length;

        RingElementPlainText[] msgBlock = new RingElementPlainText[messageBlockLength];
        msgBlock[0] = new RingElementPlainText(zp.injectiveValueOf(bytes));
        for (int i = 1; i < msgBlock.length; i++) {
            msgBlock[i] = zero;
        }

        return new MessageBlock(msgBlock);
    }

    /**
     * This method is provides functionality for testing purposes.
     * <p>
     * It generates the randomness attribute used in committing process.
     *
     * @param p prime number (typically provided by {@link PedersenPublicParameters})
     * @return {@link Zp.ZpElement} randomness
     */
    protected Zp.ZpElement generateR(BigInteger p) {
        Zp zP = new Zp(p);
        return zP.getUniformlyRandomElement();
    }

    /**
     * Returns a representation of the object of type {@link PedersenCommitmentScheme} .
     *
     * @return {@link Representation}
     */
    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public PedersenPublicParameters getPp() {
        return pp;
    }


    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        PedersenCommitmentScheme other = (PedersenCommitmentScheme) obj;

        return pp != null ? pp.equals(other.pp) : other.pp == null;
    }

    @Override
    public int hashCode() {
        return pp != null ? pp.hashCode() : 0;
    }
}

