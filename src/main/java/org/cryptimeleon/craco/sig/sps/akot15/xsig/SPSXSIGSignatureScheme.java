package org.cryptimeleon.craco.sig.sps.akot15.xsig;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11SigningKey;
import org.cryptimeleon.craco.sig.sps.kpw15.SPSKPW15Signature;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

public class SPSXSIGSignatureScheme implements MultiMessageStructurePreservingSignatureScheme {

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
            throw new IllegalArgumentException("The given message length does not match the public parameters");
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


        boolean test = verifyKeyIntegrity(vk, sk);

        return new SignatureKeyPair<>(vk, sk);
    }


    /**
     * Tests the properties of the key pair
     * */
    //TODO remove these
    private boolean verifyKeyIntegrity(SPSXSIGVerificationKey vk, SPSXSIGSigningKey sk) {

        BilinearMap bMap = pp.getBilinearMap();

        GroupElement ppe1lhs = bMap.apply(sk.getK2(), pp.getGroup2ElementH()).compute();
        GroupElement ppe1rhs = bMap.apply(pp.getGroup1ElementG(), vk.getV1()).compute();

        boolean ppe1Test = ppe1lhs.equals(ppe1rhs);

        GroupElement ppe2lhs = bMap.apply(pp.getGroup1ElementG(), vk.getV3()).compute();
        GroupElement ppe2rhs = bMap.apply(sk.getK2(), vk.getV2()).compute();

        boolean ppe2Test = ppe2lhs.equals(ppe2rhs);

        GroupElement ppe3lhs = bMap.apply(sk.K1, vk.getV1()).compute();
        GroupElement ppe3rhs = bMap.apply(vk.getV7(), vk.getV8()).compute();

        boolean ppe3Test = ppe3lhs.equals(ppe3rhs);

        GroupElement ppe4lhs = bMap.apply(sk.getK2(), vk.getV4()).compute();
        GroupElement ppe4rhs = bMap.apply(pp.getGroup1ElementG(), vk.getV5()).compute();

        boolean ppe4Test = ppe4lhs.equals(ppe4rhs);

        GroupElement ppe5lhs = bMap.apply(sk.K3, pp.getGroup2ElementH());
        ppe5lhs = ppe5lhs.op(bMap.apply(sk.K4, vk.getV2())).compute();

        GroupElement ppe5rhs = bMap.apply(pp.getGroup1ElementG(), vk.getV4()).compute();

        boolean ppe5Test = ppe5lhs.equals(ppe5rhs);

        return ppe1Test && ppe2Test && ppe3Test && ppe4Test && ppe5Test;
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {

        if(!(plainText instanceof MessageBlock)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }

        if(!(secretKey instanceof SPSXSIGSigningKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock)plainText;
        SPSXSIGSigningKey sk = (SPSXSIGSigningKey) secretKey;


        //pick randomness

        ZpElement r0 = pp.getZp().getUniformlyRandomElement();
        ZpElement r1 = pp.getZp().getUniformlyRandomElement();
        ZpElement r = r0.add(r1);
        ZpElement z = pp.getZp().getUniformlyRandomElement();

        // compute signature

        GroupElement group2ElementS0 = sk.getV6();

        for (int i = 0; i < messageBlock.length(); i++) {
            GroupElementPlainText m_i3 = ((GroupElementPlainText)((MessageBlock)messageBlock.get(i)).get(2));
            group2ElementS0 = group2ElementS0.op(m_i3.get());
        }

        group2ElementS0 = group2ElementS0.pow(r0).compute();

        GroupElement group1ElementS1 = sk.getK1().op(sk.getK3().pow(r)).compute();

        GroupElement group1ElementS2 = sk.getK4().pow(r);
        GroupElement group1ElementS2rhs = pp.getGroup1ElementG().pow(z.neg()).compute();
        group1ElementS2 = group1ElementS2.op(group1ElementS2rhs).compute();

        GroupElement group1ElementS3 = sk.getK2().pow(z).compute();

        GroupElement group1ElementS4 = sk.getK2().pow(r1).compute();

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

        // parse message

        if(!(plainText instanceof MessageBlock)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }

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

        GroupElement ppe1lhs2 = vk.getV6();

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

        GroupElement ppe2lhs = bMap.apply(sigma.getGroup1ElementsSigma()[0], vk.getV1());

        ppe2lhs = ppe2lhs.op(bMap.apply(sigma.getGroup1ElementsSigma()[1], vk.getV3()));
        ppe2lhs = ppe2lhs.op(bMap.apply(sigma.getGroup1ElementsSigma()[2], vk.getV2()));

        ppe2lhs.compute();

        //right-hand side

        GroupElement ppe2rhs = bMap.apply(sigma.getGroup1ElementsSigma()[3], vk.getV4());
        ppe2rhs = ppe2rhs.op(bMap.apply(sigma.getGroup1ElementsSigma()[4], vk.getV5()));
        ppe2rhs = ppe2rhs.op(bMap.apply(vk.getV7(), vk.getV8()));
        ppe2rhs.compute();

        return ppe2lhs.equals(ppe2rhs);
    }

    private boolean verifyThirdPPE(BilinearMap bMap, MessageBlock messageBlock) {

        for (int i = 0; i < pp.getGroup1ElementsU().length; i++) {

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

        for (int i = 0; i < pp.getGroup1ElementsU().length; i++) {

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
        return mapToPlaintext(bytes, pp.getMessageLength());
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        return mapToPlaintext(bytes, pp.getMessageLength());
    }

    private MessageBlock mapToPlaintext(byte[] bytes, int messageBlockLength){
        // returns (P^m, P, ..., P) where m = Z_p.injectiveValueOf(bytes).
        //TODO check this!
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
