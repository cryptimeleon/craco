package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.sps.SPSMessageSpaceVerifier;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

public class SPSXSIGSignatureScheme implements MultiMessageStructurePreservingSignatureScheme, SPSMessageSpaceVerifier {

    @Represented
    private SPSXSIGPublicParameters pp;

    protected SPSXSIGSignatureScheme() { super(); }

    public SPSXSIGSignatureScheme(SPSXSIGPublicParameters pp) {
        super();
        this.pp = pp;
    }

    public SPSXSIGSignatureScheme(Representation repr) { new ReprUtil(this).deserialize(repr); }

    public SPSXSIGPublicParameters getPublicParameters() { return pp; }


    @Override
    public SignatureKeyPair<SPSXSIGVerificationKey, SPSXSIGSigningKey> generateKeyPair(int numberOfMessages) {

        if(pp.getMessageLength() != numberOfMessages){
            throw new IllegalArgumentException(String.format(
                    "The scheme expected messageLength %d, but was: %d",
                    pp.getMessageLength(), numberOfMessages));
        }

        //pick randomness

        ZpElement r0 = pp.getZp().getUniformlyRandomElement();
        ZpElement r1 = pp.getZp().getUniformlyRandomElement();
        ZpElement r2 = pp.getZp().getUniformlyRandomElement();

        ZpElement phi = pp.getZp().getUniformlyRandomElement();
        ZpElement alpha = pp.getZp().getUniformlyRandomElement();

        ZpElement a = pp.getZp().getUniformlyRandomElement();
        ZpElement b = pp.getZp().getUniformlyRandomElement();

        //calculate verification key elements

        GroupElement groupElementG = pp.getGroup1ElementG();
        GroupElement groupElementGHat = pp.getGroup2ElementH();

        GroupElement group2ElementV1 = groupElementGHat.pow(b).compute();
        GroupElement group2ElementV2 = groupElementGHat.pow(a).compute();
        GroupElement group2ElementV3 = groupElementGHat.pow(a.mul(b)).compute();
        GroupElement group2ElementV4 = groupElementGHat.pow(r0.add(a.mul(r1))).compute();
        GroupElement group2ElementV5 = group2ElementV4.pow(b).compute();
        GroupElement group2ElementV6 = groupElementGHat.pow(r2).compute();

        GroupElement group1ElementV7 = groupElementG.pow(phi).compute();

        GroupElement group2ElementV8;

        if(!phi.isZero()) {
            group2ElementV8 = groupElementGHat.pow(alpha.mul(b).div(phi)).compute();
        }
        else {
            group2ElementV8 = groupElementGHat.getStructure().getUniformlyRandomElement();
        }

        //calculate signing key elements

        GroupElement group1ElementK1 = groupElementG.pow(alpha).compute();
        GroupElement group1ElementK2 = groupElementG.pow(b).compute();
        GroupElement group1ElementK3 = groupElementG.pow(r0).compute();
        GroupElement group1ElementK4 = groupElementG.pow(r1).compute();

        SPSXSIGVerificationKey vk = new SPSXSIGVerificationKey(
                group2ElementV1, group2ElementV2,
                group2ElementV3, group2ElementV4,
                group2ElementV5, group2ElementV6,
                group1ElementV7, group2ElementV8);

        SPSXSIGSigningKey sk = new SPSXSIGSigningKey(
                group2ElementV6,
                group1ElementK1, group1ElementK2,
                group1ElementK3, group1ElementK4);

        return new SignatureKeyPair<>(vk, sk);
    }


    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {

        // check if the message to be signed matches the structure required by the implementation
        doMessageChecks(plainText);

        MessageBlock messageBlock = (MessageBlock) plainText;

        if(!(secretKey instanceof SPSXSIGSigningKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }


        SPSXSIGSigningKey sk = (SPSXSIGSigningKey) secretKey;


        //pick randomness

        ZpElement r0 = pp.getZp().getUniformlyRandomElement();
        ZpElement r1 = pp.getZp().getUniformlyRandomElement();
        ZpElement r = r0.add(r1);
        ZpElement z = pp.getZp().getUniformlyRandomElement();

        // compute signature

        GroupElement group2ElementS0 = sk.getGroup2ElementV6();

        for (int i = 0; i < messageBlock.length(); i++) {
            GroupElementPlainText m_i3 = ((GroupElementPlainText)((MessageBlock)messageBlock.get(i)).get(2));
            group2ElementS0 = group2ElementS0.op(m_i3.get());
        }

        group2ElementS0 = group2ElementS0.pow(r0).compute();

        GroupElement group1ElementS1 = sk.getGroup1ElementK1().op(sk.getGroup1ElementK3().pow(r)).compute();

        GroupElement group1ElementS2 = sk.getGroup1ElementK4().pow(r);
        GroupElement group1ElementS2rhs = pp.getGroup1ElementG().pow(z.neg()).compute();
        group1ElementS2 = group1ElementS2.op(group1ElementS2rhs).compute();

        GroupElement group1ElementS3 = sk.getGroup1ElementK2().pow(z).compute();

        GroupElement group1ElementS4 = sk.getGroup1ElementK2().pow(r1).compute();

        GroupElement group1ElementS5 = pp.getGroup1ElementG().pow(r0).compute();

        return new SPSXSIGSignature(
                group2ElementS0,
                new GroupElement[]{
                        group1ElementS1, group1ElementS2,
                        group1ElementS3, group1ElementS4,
                        group1ElementS5
                });
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {

        // check if the message to be signed matches the structure required by the implementation
        doMessageChecks(plainText);

        if(!(publicKey instanceof SPSXSIGVerificationKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        if(!(signature instanceof SPSXSIGSignature)){
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }


        MessageBlock messageBlock = (MessageBlock) plainText;
        SPSXSIGVerificationKey vk = (SPSXSIGVerificationKey) publicKey;
        SPSXSIGSignature sigma = (SPSXSIGSignature) signature;

        BilinearMap bMap = pp.getBilinearMap();

        return verifyFirstPPE(bMap, sigma, vk, messageBlock)
                && verifySecondPPE(bMap, sigma, vk)
                && verifyThirdPPE(bMap, messageBlock)
                && verifyFourthPPE(bMap, messageBlock);
    }

    private boolean verifyFirstPPE(BilinearMap bMap, SPSXSIGSignature sigma,
                                   SPSXSIGVerificationKey vk, MessageBlock messageBlock) {

        GroupElement ppe1lhs2 = vk.getGroup2ElementV6();

        for (int i = 0; i < messageBlock.length(); i++) {
            GroupElementPlainText m_i3 = ((GroupElementPlainText)((MessageBlock)messageBlock.get(i)).get(2));
            ppe1lhs2 = ppe1lhs2.op(m_i3.get());
        }

        ppe1lhs2 = ppe1lhs2.compute();

        GroupElement ppe1lhs = bMap.apply(sigma.getGroup1ElementsSigma()[4], ppe1lhs2).compute();

        GroupElement ppe1rhs = bMap.apply(pp.getGroup1ElementG(), sigma.getGroup2ElementSigma0()).compute();

        return ppe1lhs.equals(ppe1rhs);
    }

    private boolean verifySecondPPE(BilinearMap bMap, SPSXSIGSignature sigma,
                                    SPSXSIGVerificationKey vk) {

        //left-hand side

        GroupElement ppe2lhs = bMap.apply(sigma.getGroup1ElementsSigma()[0], vk.getGroup2ElementV1());

        ppe2lhs = ppe2lhs.op(bMap.apply(sigma.getGroup1ElementsSigma()[1], vk.getGroup2ElementV3()));
        ppe2lhs = ppe2lhs.op(bMap.apply(sigma.getGroup1ElementsSigma()[2], vk.getGroup2ElementV2()));

        ppe2lhs.compute();

        //right-hand side

        GroupElement ppe2rhs = bMap.apply(sigma.getGroup1ElementsSigma()[3], vk.getGroup2ElementV4());
        ppe2rhs = ppe2rhs.op(bMap.apply(sigma.getGroup1ElementsSigma()[4], vk.getGroup2ElementV5()));
        ppe2rhs = ppe2rhs.op(bMap.apply(vk.getGroup1ElementV7(), vk.getGroup2ElementV8()));
        ppe2rhs.compute();

        return ppe2lhs.equals(ppe2rhs);
    }

    private boolean verifyThirdPPE(BilinearMap bMap, MessageBlock messageBlock) {

        for (int i = 0; i < messageBlock.length(); i++) {

            MessageBlock innerBlock = (MessageBlock) messageBlock.get(i);
            GroupElement m_i1 = ((GroupElementPlainText) innerBlock.get(0)).get();
            GroupElement m_i3 = ((GroupElementPlainText) innerBlock.get(2)).get();

            GroupElement ppe3lhs = bMap.apply(pp.getGroup1ElementF1(), m_i3);
            ppe3lhs.compute();

            GroupElement ppe3rhs = bMap.apply(pp.getGroup1ElementsU()[i], m_i1);
            ppe3rhs.compute();

            if(!ppe3lhs.equals(ppe3rhs)) {
                return false;
            }

        }

        return true;
    }

    private boolean verifyFourthPPE(BilinearMap bMap, MessageBlock messageBlock) {

        for (int i = 0; i < messageBlock.length(); i++) {

            MessageBlock innerBlock = (MessageBlock) messageBlock.get(i);
            GroupElement m_i2 = ((GroupElementPlainText) innerBlock.get(1)).get();
            GroupElement m_i3 = ((GroupElementPlainText) innerBlock.get(2)).get();

            GroupElement ppe3lhs = bMap.apply(pp.getGroup1ElementF2(), m_i3);
            ppe3lhs.compute();

            GroupElement ppe3rhs = bMap.apply(pp.getGroup1ElementsU()[i], m_i2);
            ppe3rhs.compute();

            if(!ppe3lhs.equals(ppe3rhs)) {
                return false;
            }

        }

        return true;
    }

    @Override
    public void doMessageChecks(PlainText plainText, int expectedMessageLength, Group expectedGroup) {
        // use implementation specific to this scheme
        doMessageChecks(plainText);
    }

    /**
     * Check if the given plainText matches the structure expected by the scheme
     *      and throws detailed exception if the plainText fails any check.
     *      Messages for this scheme require a unique structure. The message space is defined as
     *      M = {(M_11, M_12, M_13),...,(M_l1, M_l2, M_l3)} such that for all i there exists a m_i in Zp such that
     *      (M_i1, M_i2, M_i3) = (F1^mi, F2^mi, Ui^mi). (Note that all these group elements are \in G_2.)
     *
     *      This results in the scheme expecting a {@link MessageBlock}, containing inner {@link MessageBlock}s,
     *      each of which holds 3 GroupElements in G_2.
     */
    private void doMessageChecks(PlainText plainText) {
        MessageBlock messageBlock;

        // The scheme expects a MessageBlock...
        if(plainText instanceof MessageBlock) {
            messageBlock = (MessageBlock) plainText;
        }
        else {
            throw new IllegalArgumentException("The scheme requires its messages to a MessageBlock");
        }

        // ...with a size matching the public parameters...
        if(messageBlock.length() != pp.getMessageLength()) {
            throw new IllegalArgumentException(String.format(
                    "The scheme expected a message of length %d, but the size was: %d",
                    pp.getMessageLength(), messageBlock.length()
            ));
        }

        // ... containing more MessageBlocks...
        for (int i = 0; i < messageBlock.length(); i++) {
            if(!(messageBlock.get(i) instanceof MessageBlock)) {
                throw new IllegalArgumentException(String.format(
                        "The scheme requires its messages to only contain inner MessageBlocks, " +
                                "but element %d was %s",
                        i, messageBlock.get(i).getClass()
                ));
            }
            else {
                // ...each containing three elements...
                MessageBlock innerBlock = (MessageBlock) messageBlock.get(i);
                if(innerBlock.length() != 3) {
                    throw new IllegalArgumentException(String.format(
                            "The scheme requires its inner MessageBlocks to contain three elements," +
                                    " but element %d contained: %d elements",
                            i, innerBlock.length()
                    ));
                }
                else {
                    // ... each of which is a GroupElementPlaintext
                    for (int j = 0; j < innerBlock.length(); j++) {
                        if(!(innerBlock.get(j) instanceof GroupElementPlainText)) {
                            throw new IllegalArgumentException(
                                    String.format(
                                            "The scheme requires its inner MessageBlocks to contain GroupElements," +
                                                    " but element %d was of type: %s",
                                            i, messageBlock.get(i).getClass().toString()
                                    )
                            );
                        }
                        else {
                            // ... in G2.
                            GroupElementPlainText groupElementPT = (GroupElementPlainText) innerBlock.get(j);
                            if(!(groupElementPT.get().getStructure().equals(pp.getG2GroupGenerator().getStructure()))) {
                                throw new IllegalArgumentException(
                                        String.format(
                                                "Expected message elements to be in G_2," +
                                                        " but element %d in inner MessageBlock %d was in: %s",
                                                j, i, groupElementPT.get().getStructure().toString()
                                        )
                                );
                            }
                        }
                    }
                }
            }
        }

        // if no exception has been thrown at this point, we can assume the message matches the expected structure.
    }



    @Override
    public PlainText restorePlainText(Representation repr) {
        /* Messages for this scheme require a unique structure. The message space is defined as
         M = {(M_11, M_12, M_13),...,(M_l1, M_l2, M_l3)} such that for all i there exists a mi in Zp such that
        (M_i1, M_i2, M_i3) = (F1^mi, F2^mi, Ui^mi)
        */

        // we enforce this message structure by requiring the Plaintext to be a MessageBlock consisting
        // of MessageBlocks, each containing a triplet of GroupElements

        ListRepresentation messageList = (ListRepresentation) repr;

        Representation[] messageTripletsRepr = new Representation[messageList.size()];

        for (int i = 0; i < messageTripletsRepr.length; i++) {
            messageTripletsRepr[i] = (Representation) messageList.get(i);
        }

        MessageBlock[] messageTriplets = new MessageBlock[messageTripletsRepr.length];

        for (int i = 0; i < messageTripletsRepr.length; i++) {
            messageTriplets[i] = new MessageBlock(
                    messageTripletsRepr[i],
                    r -> new GroupElementPlainText(r, pp.getG2GroupGenerator().getStructure())
            );
        }

        return new MessageBlock(messageTriplets);
    }

    @Override
    public Signature restoreSignature(Representation repr) {
        return new SPSXSIGSignature(
                repr,
                pp.getG1GroupGenerator().getStructure(),
                pp.getG2GroupGenerator().getStructure());
    }

    @Override
    public SigningKey restoreSigningKey(Representation repr) {
        return new SPSXSIGSigningKey(pp.getG1GroupGenerator().getStructure(),pp.getG2GroupGenerator().getStructure(), repr);
    }

    @Override
    public VerificationKey restoreVerificationKey(Representation repr) {
        return new SPSXSIGVerificationKey(
                pp.getG1GroupGenerator().getStructure(),
                pp.getG2GroupGenerator().getStructure(),
                repr);
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {
        if(pp == null)
        {
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }

        return mapToPlaintext(bytes, pp.getMessageLength());
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        if(pp == null)
        {
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }

        return mapToPlaintext(bytes, pp.getMessageLength());
    }

    private MessageBlock mapToPlaintext(byte[] bytes, int messageBlockLength){
        // returns (P^m, P, ..., P) where m = Z_p.injectiveValueOf(bytes).

        GroupElementPlainText[] msgBlock = new GroupElementPlainText[messageBlockLength];
        msgBlock[0] = new GroupElementPlainText(
                pp.getG1GroupGenerator().pow(pp.getZp().injectiveValueOf(bytes))
        );

        for (int i = 1; i < msgBlock.length; i++) {
            msgBlock[i] = new GroupElementPlainText(pp.getG1GroupGenerator());
        }

        return new MessageBlock(new MessageBlock(msgBlock), new MessageBlock());
    }


    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getG1GroupGenerator().getStructure().size().bitLength() - 1) / 8;
    }

    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }



}
