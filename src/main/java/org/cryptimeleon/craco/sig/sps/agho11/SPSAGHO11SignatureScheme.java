package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * An a of yet unfinished implementation of the scheme originally presented in
 *
 * [1] Abe et. al.: Optimal Structure-Preserving Signatures in Asymmetric Bilinear Groups.
 * CRYPTO 2011: Advances in Cryptology – CRYPTO 2011 pp. 649-666
 * https://www.iacr.org/archive/crypto2011/68410646/68410646.pdf
 *
 * */
public class SPSAGHO11SignatureScheme implements MultiMessageStructurePreservingSignatureScheme {

    /**
     * The public parameters used by the scheme
     * */
    @Represented
    protected SPSAGHO11PublicParameters pp;


    protected SPSAGHO11SignatureScheme(){ super(); }

    public SPSAGHO11SignatureScheme(SPSAGHO11PublicParameters pp) {
        super();
        this.pp = pp;
    }

    public SPSAGHO11SignatureScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }


    @Override
    public SignatureKeyPair<SPSAGHO11VerificationKey, SPSAGHO11SigningKey> generateKeyPair(int numberOfMessages) {
        Zp zp = pp.getZp();

        //TODO adapt this for 2D Message Vectors?
        // check if number of messages is equal to the number determined by public parameters pp
        //if (!(numberOfMessages == this.pp.getNumberOfMessages())) {
        //    throw new IllegalArgumentException("Number of messages l has to be the same as in public parameters, but it is: " + numberOfMessages);
        //}

        //TODO put actual number of messages in PPs
        ZpElement[] exponentsU = IntStream.range(0, numberOfMessages).mapToObj(x -> zp.getUniformlyRandomNonzeroElement())
                .toArray(ZpElement[]::new);
        ZpElement[] exponentsW = IntStream.range(0, numberOfMessages).mapToObj(x -> zp.getUniformlyRandomNonzeroElement())
                .toArray(ZpElement[]::new);
        Zp.ZpElement exponentV = zp.getUniformlyRandomNonzeroElement();
        Zp.ZpElement exponentZ = zp.getUniformlyRandomNonzeroElement();

        // Set public key ( verification key)
        SPSAGHO11VerificationKey pk = new SPSAGHO11VerificationKey();

        // Calculate Vectors
        GroupElement[] groupElementsU = Arrays.stream(exponentsU).map(x -> pp.getG1GroupGenerator().pow(x).compute())
                .toArray(GroupElement[]::new);
        GroupElement[] groupElementsW = Arrays.stream(exponentsW).map(x -> pp.getG2GroupGenerator().pow(x).compute())
                .toArray(GroupElement[]::new);

        pk.setGroupElementsU(groupElementsU);
        pk.setGroupElementsW(groupElementsW);

        pk.setGroupElementV(pp.getG2GroupGenerator().pow(exponentV));
        pk.setGroupElementZ(pp.getG2GroupGenerator().pow(exponentZ));

        // Set secret key (signing key)
        SPSAGHO11SigningKey sk = new SPSAGHO11SigningKey(exponentsU, exponentV, exponentsW, exponentZ);

        return new SignatureKeyPair<>(pk, sk);
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {

        //The scheme signs messages on G^(k_M) x H^(k_N), so we need a MessageBlock containing 2 MessageBlocks
        MessageBlock containerBlock = (MessageBlock) plainText;
        MessageBlock messageGElements = (MessageBlock) containerBlock.get(0); //TODO this NEEDS Exception handling
        MessageBlock messageHElements = (MessageBlock) containerBlock.get(1);

        int k_M = messageGElements.length();
        int k_N = messageHElements.length();

        //cast signing key
        SPSAGHO11SigningKey sk = (SPSAGHO11SigningKey) secretKey;

        //pick randomness r \in Z*_p
        ZpElement r = pp.getZp().getUniformlyRandomNonzeroElement();

        //calculate signature components
        GroupElement sigma1R = pp.getG1GroupGenerator().pow(r).compute();

        //TODO I have no idea if this is correct. Oh well...
        GroupElement sigma2S = pp.getG1GroupGenerator().getStructure().getNeutralElement();
        for (int i = 0; i < k_M; i++) {
            sigma2S = sigma2S.op(
                    ((GroupElementPlainText) messageGElements.get(i)).get() // M_i
                            .pow(pp.getZp().getZeroElement().sub(sk.getExponentsW()[i])) // ^(-w_i)
            );
        }
        sigma2S = sigma2S.pow(sk.getExponentZ().sub(r.mul(sk.getExponentV())));
        sigma2S.compute();

        //TODO Also of questionable quality...
        GroupElement sigma3T = pp.getG2GroupGenerator().getStructure().getNeutralElement();
        for (int i = 0; i < k_N; i++) {
            sigma3T = sigma3T.op(
                    ((GroupElementPlainText) messageHElements.get(i)).get() // N_i
                            .pow(pp.getZp().getZeroElement().sub(sk.getExponentsU()[i])) // ^(-u_i)
            );
        }
        sigma3T = sigma3T.op(pp.getG2GroupGenerator()); // * H
        sigma3T = sigma3T.pow(r.inv()); // ^1/r
        sigma3T.compute();

        return new SPSAGHO11Signature(sigma1R, sigma2S, sigma3T);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {

        //TODO exception handling
        MessageBlock containerBlock = (MessageBlock) plainText;
        MessageBlock messageGElements = (MessageBlock) containerBlock.get(0);
        MessageBlock messageHElements = (MessageBlock) containerBlock.get(1);


        SPSAGHO11Signature sigma = (SPSAGHO11Signature) signature;
        SPSAGHO11VerificationKey pk = (SPSAGHO11VerificationKey) publicKey;

        return evaluateFirstPPE(messageGElements, sigma, pk)
                && evaluateSecondPPE(messageHElements, sigma, pk);
    }

    private boolean evaluateFirstPPE(MessageBlock messageBlock, SPSAGHO11Signature sigma, SPSAGHO11VerificationKey pk){

        BilinearMap bMap = pp.getBilinearMap();

        //left-hand side
        GroupElement lhs1 = bMap.apply(sigma.getGroup1ElementSigma1R(), pk.getGroupElementV());
        lhs1 = lhs1.op(bMap.apply(sigma.getGroup1ElementSigma2S(), pp.getG2GroupGenerator()));

        GroupElement lhs2 = pp.getGT().getNeutralElement();

        for (int i = 0; i < messageBlock.length(); i++) {
            lhs2 = lhs2.op(
                    bMap.apply(((GroupElementPlainText)messageBlock.get(i)).get(), pk.getGroupElementsW()[i])
            );
        }

        GroupElement lhs = lhs1.op(lhs2);
        lhs.compute();

        // right-hand side
        GroupElement rhs = bMap.apply(pp.getG1GroupGenerator(), pk.getGroupElementZ());
        rhs.compute();


        return lhs.equals(rhs);
    }

    private boolean evaluateSecondPPE(MessageBlock messageBlock, SPSAGHO11Signature sigma, SPSAGHO11VerificationKey pk){

        BilinearMap bMap = pp.getBilinearMap();

        //left-hand side
        GroupElement lhs1 = bMap.apply(sigma.getGroup1ElementSigma1R(), sigma.getGroup2ElementSigma3T());

        GroupElement lhs2 = pp.getGT().getNeutralElement();

        for (int i = 0; i < messageBlock.length(); i++) {
            lhs2 = lhs2.op(
                    bMap.apply(pk.getGroupElementsU()[i], ((GroupElementPlainText)messageBlock.get(i)).get())
            );
        }

        GroupElement lhs = lhs1.op(lhs2);
        lhs.compute();

        //right-hand side
        GroupElement rhs = bMap.apply(pp.getG1GroupGenerator(), pp.getG2GroupGenerator());
        rhs.compute();


        return lhs.equals(rhs);
    }

    @Override
    public PlainText restorePlainText(Representation repr) {
        //TODO this is taken from the Groth15 implementation. Not sure if it fits here
        return new MessageBlock(repr, r -> new GroupElementPlainText(r, pp.getG1GroupGenerator().getStructure()));
    }

    @Override
    public Signature restoreSignature(Representation repr) {
        return new SPSAGHO11Signature(repr
                , this.pp.getG1GroupGenerator().getStructure()
                , this.pp.getG2GroupGenerator().getStructure());
    }

    @Override
    public SigningKey restoreSigningKey(Representation repr) {
        return new SPSAGHO11SigningKey(repr, this.pp.getZp());
    }

    @Override
    public VerificationKey restoreVerificationKey(Representation repr) {
        return new SPSAGHO11VerificationKey(this.pp.getG1GroupGenerator().getStructure(),
                this.pp.getG2GroupGenerator().getStructure(),
                repr);
    }


    @Override
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return null; //TODO
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        return null; //TODO
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return 0; //TODO
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
