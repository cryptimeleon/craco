package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15OpenValue;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.RingElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;

/**
 * An implementation of the gamma binding commitment scheme presented in
 *
 * TODO
 *
 */
public class TCGAKOT15CommitmentScheme implements CommitmentScheme {

    public TCGAKOT15PublicParameters pp; //TODO not public

    private TCGAKOT15CommitmentKey commitmentKey;


    public TCGAKOT15CommitmentScheme(TCGAKOT15PublicParameters pp) {
        this.pp = pp;
        commitmentKey = generateKey();
    }

    /**
     * Generate a commitment key to be used by the scheme
     * */
    private TCGAKOT15CommitmentKey generateKey() {

        GroupElement[] group2ElementsXi = new GroupElement[pp.getMessageLength()];

        for (int i = 0; i < group2ElementsXi.length; i++) {
            group2ElementsXi[i] = pp.getG2GroupGenerator().pow(pp.getZp().getUniformlyRandomElement()).compute();
        }

        return new TCGAKOT15CommitmentKey(group2ElementsXi);
    }

    public TCGAKOT15CommitmentKey getCommitmentKey() {
        return commitmentKey;
    }


    /**
     * Commit to a given message
     *
     * @param plainText the message block
     *
     * @return the commitment to the plaintext as would be calculated by TC-gamma
     * */
    @Override
    public CommitmentPair commit(PlainText plainText) {

        if(!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("this is not a valid message for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;

        Zp.ZpElement zeta = pp.getZp().getUniformlyRandomElement();

        GroupElement group2ElementGu = pp.getG2GroupGenerator().pow(zeta);

        for (int i = 0; i < messageBlock.length(); i++) {
            GroupElement Xi = commitmentKey.getGroup2ElementsXi()[i];
            RingElement mi = ((RingElementPlainText)messageBlock.get(i)).getRingElement();
            group2ElementGu = group2ElementGu.op(Xi.pow(mi));
        }
        group2ElementGu.compute();

        return new CommitmentPair(new TCGAKOT15Commitment(group2ElementGu), new TCGAKOT15OpenValue(pp.getG1GroupGenerator().pow(zeta).compute()));
    }

    @Override
    public boolean verify(Commitment commitment, OpenValue openValue, PlainText plainText) {

        if(!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("this is not a valid message for this scheme");
        }

        if(!(commitment instanceof TCGAKOT15Commitment)) {
            throw new IllegalArgumentException("this is not a valid commitment for this scheme");
        }

        if(!(openValue instanceof TCGAKOT15OpenValue)) {
            throw new IllegalArgumentException("this is not a valid opening for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        TCGAKOT15Commitment com = (TCGAKOT15Commitment) commitment;
        TCGAKOT15OpenValue open = (TCGAKOT15OpenValue) openValue;

        if(!(pp.getMessageLength().equals(messageBlock.length()))){
            throw new IllegalArgumentException(
                    String.format(
                            "public parameters do not match given message length : %d vs. %d",
                            pp.getMessageLength(),
                            messageBlock.length())
            );
        }


        GroupElement[] messageGroupElements = new GroupElement[messageBlock.length()];

        //if RingElements are provided, transform the message to feature group elements
        if(messageBlock.get(0) instanceof RingElementPlainText) {
            messageGroupElements = messageBlock.stream().map(
                    x -> pp.getG1GroupGenerator().pow(((RingElementPlainText)x).getRingElement()).compute()).toArray(GroupElement[]::new);
        }else if(messageBlock.get(0) instanceof GroupElementPlainText) {
            messageGroupElements = messageBlock.stream().map(x -> ((GroupElementPlainText)x).get()).toArray(GroupElement[]::new);
        }


        BilinearMap bMap = pp.getBilinearMap();

        GroupElement ppe_lhs = bMap.apply(pp.getG1GroupGenerator(), com.getGroup2ElementGu()).compute();

        GroupElement ppe_rhs = bMap.apply(open.getGroup1ElementR(), pp.getG2GroupGenerator());

        for (int i = 0; i < messageBlock.length(); i++) {
            ppe_rhs = ppe_rhs.op(bMap.apply(
                    messageGroupElements[i],
                    commitmentKey.getGroup2ElementsXi()[i])
            );
        }
        ppe_rhs.compute();

        return ppe_lhs.equals(ppe_rhs);
    }

    @Override
    public PlainText mapToPlainText(byte[] bytes) {
        RingElementPlainText zero = new RingElementPlainText(pp.getZp().getZeroElement());
        return new MessageBlock(
                Vector.of(new RingElementPlainText(pp.getZp().injectiveValueOf(bytes)))
                        .pad(zero, pp.getMessageLength())
        );
    }


    @Override
    public Commitment restoreCommitment(Representation repr) {
        return new TCGAKOT15Commitment(pp.getG2GroupGenerator().getStructure(), repr);
    }

    @Override
    public OpenValue restoreOpenValue(Representation repr) {
        return new TCGAKOT15OpenValue(pp.getG1GroupGenerator().getStructure(), repr);
    }

    @Override
    public Representation getRepresentation() {
        return new ReprUtil(this).serialize();
    }

}
