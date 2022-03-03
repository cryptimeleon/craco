package org.cryptimeleon.craco.sig.sps.akot15.tcgamma;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.RingElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;

/**
 * An implementation of the gamma binding commitment scheme presented in [1]
 * While the scheme is intended to be a building block of the larger SPS scheme
 * {@link org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2SignatureScheme},
 * the implementation can be used on its own, where it is gamma-collision resistant
 * under the Double Pairing assumption as defined in [1].
 *
 *
 * Note: The calculation of the commitments differs slightly when the scheme is used in the context of
 * {@link org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2SignatureScheme}:
 *      As the scheme combines {@link org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15CommitmentScheme} -- which is
 *      based on this scheme -- with {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme},
 *      the scheme must calculate 2 additional elements for its commitments (with are then signed by XSIG).
 *
 * Note: While the message space of the verification function is M := {M_i \in G_1}, this implementation will
 *      also accept messages containing elements \in Z_p and will calculate the appropriate G_1 elements automatically.
 *
 * [1] Abe et al.: Fully Structure-Preserving Signatures and Shrinking Commitments.
 * https://eprint.iacr.org/2015/076.pdf
 *
 */
public class TCGAKOT15CommitmentScheme implements CommitmentScheme {

    /**
     * The public parameters for this scheme
     */
    @Represented
    private AKOT15SharedPublicParameters pp;

    /**
     * In order to match the {@link CommitmentScheme} interface, the scheme stores its own keys
     * instead of the key passed as a parameter of commit() / verify().
     */
    private TCGAKOT15CommitmentKey commitmentKey;

    public TCGAKOT15CommitmentScheme(AKOT15SharedPublicParameters pp) {
        this.pp = pp;
        commitmentKey = generateKey();
    }

    public TCGAKOT15CommitmentScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    /**
     * Generate a commitment key to be used by the scheme.
     * */
    private TCGAKOT15CommitmentKey generateKey() {

        GroupElement[] group2ElementsXi = new GroupElement[pp.getMessageLength()];

        //if XSIG specific parameters are passed, additional values are calculated
        if(pp instanceof TCGAKOT15XSIGPublicParameters) {

            TCGAKOT15XSIGPublicParameters ppXSIG = (TCGAKOT15XSIGPublicParameters) pp;

            GroupElement[] group2ElementsXi2 = new GroupElement[pp.getMessageLength()];
            GroupElement[] group2ElementsXi3 = new GroupElement[pp.getMessageLength()];

            for (int i = 0; i < group2ElementsXi.length; i++) {

                Zp.ZpElement rho = pp.getZp().getUniformlyRandomElement();

                group2ElementsXi[i] = pp.getG2GroupGenerator().pow(rho).compute();
                group2ElementsXi2[i] = ppXSIG.getGroup2ElementF2().pow(rho).compute();
                group2ElementsXi3[i] = ppXSIG.getGroup2ElementU1().pow(rho).compute();
            }

            return new TCGAKOT15XSIGCommitmentKey(group2ElementsXi, group2ElementsXi2, group2ElementsXi3);
        }
        else {

            for (int i = 0; i < group2ElementsXi.length; i++) {
                group2ElementsXi[i] = pp.getG2GroupGenerator().pow(pp.getZp().getUniformlyRandomElement()).compute();
            }

            return new TCGAKOT15CommitmentKey(group2ElementsXi);
        }
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

        // check if the message matches the expected structure. commit() requires its messages to contain RingElements.
        doMessageChecks(plainText, true);

        MessageBlock messageBlock = (MessageBlock) plainText;
        Zp.ZpElement zeta = pp.getZp().getUniformlyRandomElement();

        TCGAKOT15OpenValue open = new TCGAKOT15OpenValue(pp.getG1GroupGenerator().pow(zeta).compute());

        //if XSIG message space is detected, compute additional values
        if(pp instanceof TCGAKOT15XSIGPublicParameters) {
            return commitXSIGVariant(messageBlock, zeta, open);
        }
        else {
            GroupElement group2ElementGu = pp.getG2GroupGenerator().pow(zeta);

            for (int i = 0; i < messageBlock.length(); i++) {
                GroupElement Xi = commitmentKey.getGroup2ElementsXi()[i];
                RingElement mi = ((RingElementPlainText)messageBlock.get(i)).getRingElement();
                group2ElementGu = group2ElementGu.op(Xi.pow(mi));
            }
            group2ElementGu.compute();

            return new CommitmentPair(new TCGAKOT15Commitment(group2ElementGu), open);
        }
    }

    /**
     * if the scheme is used in the context of
     * {@link org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2SignatureScheme}, the scheme is required to calculate
     * two additional elements, so they can later be passed to
     * {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme}.
     *
     */
    private CommitmentPair commitXSIGVariant(MessageBlock messageBlock, Zp.ZpElement zeta, TCGAKOT15OpenValue open) {

        TCGAKOT15XSIGCommitmentKey ck = (TCGAKOT15XSIGCommitmentKey) commitmentKey;
        TCGAKOT15XSIGPublicParameters ppXSIG = (TCGAKOT15XSIGPublicParameters) pp;

        // compute G_u

        GroupElement group2ElementGu = pp.getG2GroupGenerator().pow(zeta);
        GroupElement group2ElementGu2 = ppXSIG.getGroup2ElementF2().pow(zeta);
        GroupElement group2ElementGu3 = ppXSIG.getGroup2ElementU1().pow(zeta);

        for (int i = 0; i < messageBlock.length(); i++) {

            RingElement mi = ((RingElementPlainText)messageBlock.get(i)).getRingElement();

            GroupElement Xi = ck.getGroup2ElementsXi()[i];
            GroupElement Xi2 = ck.getGroup2ElementsXi2()[i];
            GroupElement Xi3 = ck.getGroup2ElementsXi3()[i];

            group2ElementGu = group2ElementGu.op(Xi.pow(mi));
            group2ElementGu2 = group2ElementGu2.op(Xi2.pow(mi));
            group2ElementGu3 = group2ElementGu3.op(Xi3.pow(mi));
        }

        group2ElementGu.compute();
        group2ElementGu2.compute();
        group2ElementGu3.compute();

        return new CommitmentPair(
                new TCGAKOT15XSIGCommitment(group2ElementGu, group2ElementGu2, group2ElementGu3),
                open);
    }


    @Override
    public boolean verify(Commitment commitment, OpenValue openValue, PlainText plainText) {

        doMessageChecks(plainText, false);

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
                    x -> pp.getG1GroupGenerator().pow(((RingElementPlainText)x).getRingElement()).compute())
                    .toArray(GroupElement[]::new);
        }else if(messageBlock.get(0) instanceof GroupElementPlainText) {
            messageGroupElements = messageBlock.stream().map(x -> ((GroupElementPlainText)x).get())
                    .toArray(GroupElement[]::new);
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

    /**
     * Check if the given plainText matches the structure expected by the scheme
     *      and throws detailed exception if the plainText fails any check.
     *
     *      Note that this scheme -- unlike every other scheme in the {@link org.cryptimeleon.craco.sig.sps.akot15}
     *      package -- operates on {@link org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement}s for its
     *      commit function.
     *      For this implementation, the verification function permits either RingElements or GroupElements
     *
     * @param requireZpElements defines if the function checking the message require the message
     *                          to contain only ZpElements
     */
    private void doMessageChecks(PlainText plainText, boolean requireZpElements) {

        MessageBlock messageBlock;

        // The scheme expects a MessageBlock...
        if(plainText instanceof MessageBlock) {
            messageBlock = (MessageBlock) plainText;
        }
        else {
            throw new IllegalArgumentException("The scheme requires its messages to a MessageBlock");
        }

        // ... with a size that matches its public parameters.
        if(messageBlock.length() != pp.getMessageLength()) {
            throw new IllegalArgumentException(String.format(
                    "The scheme expected a message of length %d, but the size was: %d",
                    pp.getMessageLength(), messageBlock.length()
            ));
        }

        // if the function permits either RingElements or GroupElements, set the message space according to the first
        // element of the message
        if(!requireZpElements) {
            if(messageBlock.get(0) instanceof RingElementPlainText)
                requireZpElements = true;
        }

        // if we expect RingElements, make sure all message elements are RingElements...
        if(requireZpElements) {
            for (int i = 0; i < messageBlock.length(); i++) {
                if(!(messageBlock.get(i) instanceof RingElementPlainText)) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "The scheme expected its Messages to contain RingElements," +
                                            " but element %d was of type: %s",
                                    i, messageBlock.get(i).getClass().toString()
                            )
                    );
                }

                // ... \in Zp as defined by the public parameters
                RingElementPlainText ringElementPT = (RingElementPlainText) messageBlock.get(i);

                if(!(ringElementPT.getRingElement().getStructure().equals(pp.getZp()))) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "The scheme expected RingElements in %s," +
                                            " but element %d was in: %s",
                                    pp.getZp().toString(),
                                    i,
                                    ringElementPT.getRingElement().getStructure().toString()
                            )
                    );
                }

            }
        }
        // if we expect GroupElements, make sure all message elements are GroupElements...
        else {
            for (int i = 0; i < messageBlock.length(); i++) {
                if(!(messageBlock.get(i) instanceof GroupElementPlainText)) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "The scheme expected its Messages to contain GroupElements," +
                                            " but element %d was of type: %s",
                                    i, messageBlock.get(i).getClass().toString()
                            )
                    );
                }

                // in G_1.
                GroupElementPlainText group1ElementPT = (GroupElementPlainText) messageBlock.get(i);

                if(!(group1ElementPT.get().getStructure().equals(pp.getG1GroupGenerator().getStructure()))) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "The scheme expected GroupElements in %s," +
                                            " but element %d was in: %s",
                                    pp.getG1GroupGenerator().getStructure().toString(),
                                    i,
                                    group1ElementPT.get().getStructure().toString()
                            )
                    );
                }

            }
        }

        // if no exception has been thrown at this point, we can assume the message matches the expected structure.
    }


    public TCGAKOT15CommitmentKey getCommitmentKey() {
        return commitmentKey;
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes) {
        RingElementPlainText zero = new RingElementPlainText(pp.getZp().getZeroElement());
        return new MessageBlock(
                Vector.of(new RingElementPlainText(pp.getZp().injectiveValueOf(bytes)))
                        .pad(zero, pp.getMessageLength())
        );
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getG1GroupGenerator().getStructure().size().bitLength() - 1) / 8;
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
