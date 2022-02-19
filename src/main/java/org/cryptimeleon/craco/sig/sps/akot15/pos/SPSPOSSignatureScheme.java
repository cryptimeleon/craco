package org.cryptimeleon.craco.sig.sps.akot15.pos;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

public class SPSPOSSignatureScheme implements MultiMessageStructurePreservingSignatureScheme {

    private AKOT15SharedPublicParameters pp;

    private GroupElement getG1GroupGenerator() {
        return (pp instanceof SPSXSIGPublicParameters) ? ((SPSXSIGPublicParameters)pp).getGroup1ElementF1() : pp.getG1GroupGenerator();
    }

    private GroupElement getG2GroupGenerator() {
        return (pp instanceof SPSXSIGPublicParameters) ? ((SPSXSIGPublicParameters)pp).getGroup2ElementF1() : pp.getG2GroupGenerator();
    }

    public SPSPOSSignatureScheme(AKOT15SharedPublicParameters pp) {
        super();
        this.pp = pp;
    }


    @Override
    public SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey> generateKeyPair(int numberOfMessages) {

        if(numberOfMessages != pp.getMessageLength()) {
            throw new IllegalArgumentException(
                    String.format(
                            "The number of messages did not match the expected message length in the public parameters: %d vs. %d",
                            numberOfMessages,
                            pp.getMessageLength()
                            )
            );
        }

        //pick randomness
        ZpElement exponentW = pp.getZp().getUniformlyRandomNonzeroElement();
        ZpElement[] exponentsChi = IntStream.range(0, numberOfMessages).mapToObj(
                x-> pp.getZp().getUniformlyRandomNonzeroElement()).toArray(ZpElement[]::new);

        GroupElement group1ElementW = getG1GroupGenerator().pow(exponentW).compute();
        GroupElement[] group1ElementsChi = Arrays.stream(exponentsChi).map(
                x-> getG1GroupGenerator().pow(x).compute()).toArray(GroupElement[]::new);

        SPSPOSSigningKey sk = new SPSPOSSigningKey(exponentsChi, exponentW);
        SPSPOSVerificationKey vk = new SPSPOSVerificationKey(group1ElementsChi, group1ElementW);

        SignatureKeyPair<SPSPOSVerificationKey,SPSPOSSigningKey> keyPair = new SignatureKeyPair<>(vk, sk);

        // Set up initial one-time key
        updateOneTimeKey(keyPair);

        return keyPair;
    }

    public void updateOneTimeKey(SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey> keyPair) {

        //pick randomness
        ZpElement exponentA = pp.getZp().getUniformlyRandomElement();
        GroupElement group1ElementA = getG1GroupGenerator().pow(exponentA).compute();

        //put into keys

        keyPair.getSigningKey().setOneTimeKey(exponentA);
        keyPair.getVerificationKey().SetOneTimeKey(group1ElementA);
    }

    @Override
    public SPSPOSSignature sign(PlainText plainText, SigningKey secretKey) {

        if(!(secretKey instanceof SPSPOSSigningKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        SPSPOSSigningKey sk = (SPSPOSSigningKey) secretKey;

        return sign(plainText, sk, sk.getOneTimeKey());
    }

    public SPSPOSSignature sign(PlainText plainText, SigningKey secretKey, ZpElement oneTimeKey) {

        if(!(plainText instanceof MessageBlock)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }

        if(!(secretKey instanceof SPSPOSSigningKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        SPSPOSSigningKey sk = (SPSPOSSigningKey) secretKey;

        if(messageBlock.length() != pp.getMessageLength()) {
            throw new IllegalArgumentException("The given message does not match the expected message length of the public parameters");
        }

        ZpElement exponentZeta = pp.getZp().getUniformlyRandomNonzeroElement();

        GroupElement group1ElementSigmaZ = getG2GroupGenerator().pow(exponentZeta).compute();

        // calculate exponent of the left side of R
        ZpElement lhsExponent = oneTimeKey;
        lhsExponent = lhsExponent.sub(exponentZeta.mul(sk.getExponentW()));

        GroupElement group1ElementSigmaR = getG2GroupGenerator().pow(lhsExponent);

        for (int i = 0; i < messageBlock.length(); i++) {
            GroupElement m_i = ((GroupElementPlainText)messageBlock.get(i)).get();
            group1ElementSigmaR = group1ElementSigmaR.op(m_i.pow(sk.getExponentsChi()[i].neg()));
        }

        group1ElementSigmaR.compute();


        return new SPSPOSSignature(group1ElementSigmaZ, group1ElementSigmaR);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {

        if(!(publicKey instanceof SPSPOSVerificationKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        SPSPOSVerificationKey vk = (SPSPOSVerificationKey) publicKey;

        return verify(plainText, signature, publicKey, vk.getOneTimeKey());
    }

    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey, GroupElement oneTimeVerificationKey) {

        if(!(plainText instanceof MessageBlock)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }

        if(!(publicKey instanceof SPSPOSVerificationKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        if(!(signature instanceof SPSPOSSignature)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        SPSPOSVerificationKey vk = (SPSPOSVerificationKey) publicKey;
        SPSPOSSignature sigma = (SPSPOSSignature) signature;

        if(messageBlock.length() != pp.getMessageLength()) {
            throw new IllegalArgumentException("The given message does not match the expected message length of the public parameters");
        }

        BilinearMap bMap = pp.getBilinearMap();

        //check PPE

        //this should throw an exception if the OT key was already used TODO check that
        GroupElement ppelhs = bMap.apply(oneTimeVerificationKey, getG2GroupGenerator()).compute();

        GroupElement pperhs = bMap.apply(vk.getGroup1ElementW(), sigma.getGroup2ElementZ());
        pperhs = pperhs.op(bMap.apply(getG1GroupGenerator(), sigma.getGroup2ElementR()));

        for (int i = 0; i < messageBlock.length(); i++) {
            GroupElement m_i = ((GroupElementPlainText)messageBlock.get(i)).get();
            pperhs = pperhs.op(bMap.apply(vk.getGroup1ElementsChi()[i],m_i));
        }
        pperhs.compute();

        return ppelhs.equals(pperhs);
    }

    @Override
    public PlainText restorePlainText(Representation repr) {
        return new MessageBlock(repr, r -> new GroupElementPlainText(r, getG2GroupGenerator().getStructure()));
    }

    @Override
    public Signature restoreSignature(Representation repr) {
        return new SPSPOSSignature(repr, getG2GroupGenerator().getStructure());
    }

    @Override
    public SigningKey restoreSigningKey(Representation repr) {
        return new SPSPOSSigningKey(repr, pp.getZp());
    }

    @Override
    public VerificationKey restoreVerificationKey(Representation repr) {
        return new SPSPOSVerificationKey(repr, getG1GroupGenerator().getStructure());
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {

        if(pp == null) {
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }

        return mapToPlainText(bytes, pp.getMessageLength());
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {

        if(pp == null) {
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }

        return mapToPlainText(bytes, pp.getMessageLength());
    }

    private MessageBlock mapToPlainText(byte[] bytes, int messageBlockLength) {
        // returns (P^m, P, ..., P) where m = Z_p.injectiveValueOf(bytes).

        GroupElementPlainText[] msgBlock = new GroupElementPlainText[messageBlockLength];
        msgBlock[0] = new GroupElementPlainText(
                getG2GroupGenerator().pow(pp.getZp().injectiveValueOf(bytes))
        );
        for (int i = 1; i < messageBlockLength; i++) {
            msgBlock[i] = new GroupElementPlainText(getG2GroupGenerator());
        }

        return new MessageBlock(msgBlock);
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (getG2GroupGenerator().getStructure().size().bitLength() - 1) / 8;
    }


    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSPOSSignatureScheme that = (SPSPOSSignatureScheme) o;
        return Objects.equals(pp, that.pp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pp);
    }

}
