package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
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
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;


/**
 * This class provides a java implementation for Pedersen Commitment Scheme. It realizes the general
 * {@link CommitmentScheme} interface and provides a concrete Pedersen Commitment Scheme implementation
 * for (commit, open) methods.
 */
public class PedersenCommitmentScheme implements CommitmentScheme {

    @Represented
    private PedersenPublicParameters pp;

    /**
     * Construct a new PedersenCommitmentScheme object providing {@link PedersenPublicParameters} as argument
     *
     * @param pp {@link PedersenPublicParameters}
     */
    public PedersenCommitmentScheme(PedersenPublicParameters pp) {
        this.pp = pp;
    }

    /**
     * Construct a new PedersenCommitmentScheme object providing {@link Representation} object
     *
     * @param representation {@link Representation}
     */
    public PedersenCommitmentScheme(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * The committing process accepts an object of type {@link PlainText}. Thus, two concrete objects can be passed
     * as input to this method, namely: {@link RingElementPlainText} (single-message) or
     * {@link MessageBlock} (multi-message).
     * The method makes use of the attributes encapsulated within
     * {@link PedersenPublicParameters} and stored in {@link #pp} member attribute.
     *
     * @param plainText object of type {@link MessageBlock} or {@link RingElementPlainText}
     * @return {@link PedersenCommitmentPair} the result of commit process
     */
    @Override
    public PedersenCommitmentPair commit(PlainText plainText) {
        if (plainText instanceof RingElementPlainText)
            plainText = new MessageBlock(plainText);


        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid PlainText for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;

        if (!(messageBlock.size() == pp.getH().length)) {
            throw new UnsupportedOperationException("The message list and parameter list lengths are not compatible!");
        }
        // Generate r
        Zp zP = pp.getZp();
        Zp.ZpElement r = generateR(pp.getP());

        // Compute c
        GroupElement g = pp.getG();
        GroupElementExpression c = new GroupPowExpr(
                new GroupElementConstantExpr(g),
                new ExponentConstantExpr(r)
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
            c = new GroupOpExpr(c, new GroupPowExpr(
                    new GroupElementConstantExpr(hi),
                    new ExponentConstantExpr(mi)
            ));
        }
        // Construct the commitment object
        PedersenOpenValue openValue = new PedersenOpenValue(messagesInZp, r);
        PedersenCommitmentValue com = new PedersenCommitmentValue(c.evaluate());
        return new PedersenCommitmentPair(com, openValue);
    }

    /**
     * This private function opens the commitment ({@link PedersenCommitmentValue}) to a message with a given
     * {@link OpenValue} and returns a {@link Zp.ZpElement}. This is done by checking that the messages in
     * {@link PedersenOpenValue} conforms to the {@link PedersenCommitmentValue}.
     *
     * @param pedersenCommitmentValue {@link PedersenCommitmentValue}
     * @param pedersenOpenValue       {@link PedersenOpenValue}
     * @return Array of opened messages of type {@link Zp.ZpElement} or null if the open failed.
     */
    private Zp.ZpElement[] open(PedersenCommitmentValue pedersenCommitmentValue, PedersenOpenValue pedersenOpenValue) {
        Zp.ZpElement[] messages = pedersenOpenValue.getMessages();
        GroupElement g = pp.getG();
        GroupElementExpression result = new GroupPowExpr(
                new GroupElementConstantExpr(g),
                new ExponentConstantExpr(pedersenOpenValue.getRandomValue())
        );
        Zp.ZpElement mi;
        GroupElement hi;
        for (int i = 0; i < messages.length; i++) {
            mi = messages[i];
            hi = pp.getH()[i];
            result = new GroupOpExpr(result, new GroupPowExpr(
                    new GroupElementConstantExpr(hi),
                    new ExponentConstantExpr(mi)
            ));
        }
        GroupElement c = pedersenCommitmentValue.getCommitmentElement();
        return c.equals(result.evaluate()) ? pedersenOpenValue.getMessages() : null;
    }

    /**
     * This function performs the opening phase of the committing process. It first verifies that the messages in the
     * open value {@link PedersenOpenValue} conform to the {@link PedersenCommitmentValue} and then checks the
     * equality of the opened messages to the messages provided by the {@link PlainText} input (announced message).
     *
     * @param commitmentValue {@link PedersenCommitmentValue}
     * @param openValue       {@link PedersenOpenValue}
     * @param plainText       {@link PlainText} (announced message)
     * @return boolean value whether the opening process is successful (true) or not (false)
     */
    @Override
    public boolean verify(CommitmentValue commitmentValue, OpenValue openValue, PlainText plainText) {
        if (plainText instanceof RingElementPlainText)
            plainText = new MessageBlock(plainText);


        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid PlainText for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;

        if (!(commitmentValue instanceof PedersenCommitmentValue) || !(openValue instanceof PedersenOpenValue)) {
            return false;
        }

        Zp.ZpElement[] openedMessages = this.open((PedersenCommitmentValue) commitmentValue, (PedersenOpenValue)
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

