package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

/**
 * An a of yet unfinished implementation of the scheme originally presented in
 *
 * [1] Abe et. al.: Optimal Structure-Preserving Signatures in Asymmetric Bilinear Groups.
 * CRYPTO 2011: Advances in Cryptology – CRYPTO 2011 pp. 649-666
 * https://www.iacr.org/archive/crypto2011/68410646/68410646.pdf
 *
 * */
public class SPSAGHO11SignatureScheme implements StandardMultiGroupMultiMessageStructurePreservingSignatureScheme {

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
    public SignatureKeyPair<SPSAGHO11VerificationKey, SPSAGHO11SigningKey> generateKeyPair(int numberOfMessages)
    {
        return generateKeyPair(numberOfMessages, 2);
    }

    @Override
    public SignatureKeyPair<SPSAGHO11VerificationKey, SPSAGHO11SigningKey> generateKeyPair(int... messageBlockLengths) {

        Zp zp = pp.getZp();

        if(!(messageBlockLengths.length == 2)){
            throw new IllegalArgumentException(String.format(
                    "The signature scheme AGHO11 expects to sign elements" +
                            " on two vectors G^M, H^N, but received: {0} vectors", messageBlockLengths.length)
            );
        }

        for (int i = 0; i < messageBlockLengths.length; i++) {
            if(!(messageBlockLengths[i] == pp.getMessageLengths()[i])){
                throw new IllegalArgumentException("The given messageBlockLengths do not match the public parameters");
            }
        }

        ZpElement[] exponentsU = IntStream.range(0, messageBlockLengths[1]).mapToObj( //note that u_1 ... u_k_N
                x -> zp.getUniformlyRandomNonzeroElement())
                .toArray(ZpElement[]::new);
        ZpElement[] exponentsW = IntStream.range(0, messageBlockLengths[0]).mapToObj( //and that w_1 ... w_k_M
                x -> zp.getUniformlyRandomNonzeroElement())
                .toArray(ZpElement[]::new);

        Zp.ZpElement exponentV = zp.getUniformlyRandomNonzeroElement();
        Zp.ZpElement exponentZ = zp.getUniformlyRandomNonzeroElement();

        // Set public key ( verification key)
        SPSAGHO11VerificationKey pk = new SPSAGHO11VerificationKey();

        // Calculate Vectors
        GroupElement[] groupElementsU = Arrays.stream(exponentsU).map(
                x -> pp.getG1GroupGenerator().pow(x).compute())
                .toArray(GroupElement[]::new);
        GroupElement[] groupElementsW = Arrays.stream(exponentsW).map(
                x -> pp.getG2GroupGenerator().pow(x).compute())
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

        if(!(plainText instanceof MessageBlock)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }

        if(!(((MessageBlock) plainText).length() == 2)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme.");
        }

        if(!(secretKey instanceof SPSAGHO11SigningKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        //TODO check if the message structure corresponds with the pps

        //The scheme signs messages on G^(k_M) x H^(k_N), so we need a MessageBlock containing 2 MessageBlocks
        MessageBlock containerBlock = (MessageBlock) plainText;
        MessageBlock messageGElements = (MessageBlock) containerBlock.get(0);
        MessageBlock messageHElements = (MessageBlock) containerBlock.get(1);

        int k_M = messageGElements.length();
        int k_N = messageHElements.length();

        //cast signing key
        SPSAGHO11SigningKey sk = (SPSAGHO11SigningKey) secretKey;

        //pick randomness r \in Z*_p
        ZpElement r = pp.getZp().getUniformlyRandomNonzeroElement();

        //calculate signature components
        GroupElement sigma1R = pp.getG1GroupGenerator().pow(r).compute();

        // sub is actually needed here
        GroupElement sigma2S1 = pp.getG1GroupGenerator().pow(sk.getExponentZ().sub(r.mul(sk.getExponentV())));

        GroupElement sigma2S2 = pp.getG1GroupGenerator().getStructure().getNeutralElement();

        for (int i = 0; i < k_M; i++) {
            sigma2S2 = sigma2S2.op(
                    ((GroupElementPlainText) messageGElements.get(i)).get() // M_i
                            .pow(sk.getExponentsW()[i].neg()) // ^(-w_i)
            );
        }

        GroupElement sigma2S = sigma2S1.op(sigma2S2);

        sigma2S.compute();

        GroupElement sigma3T = pp.getG2GroupGenerator().getStructure().getNeutralElement();
        for (int i = 0; i < k_N; i++) {
            sigma3T = sigma3T.op(
                    ((GroupElementPlainText) messageHElements.get(i)).get() // N_i
                            .pow(sk.getExponentsU()[i].neg()) // ^(-u_i)
            );
        }
        sigma3T = sigma3T.op(pp.getG2GroupGenerator()); // * H
        sigma3T = sigma3T.pow(r.inv()); // ^1/r
        sigma3T.compute();

        return new SPSAGHO11Signature(sigma1R, sigma2S, sigma3T);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {

        if(!(plainText instanceof MessageBlock)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }

        if(!(((MessageBlock) plainText).length() == 2)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme.");
        }

        if(!(signature instanceof SPSAGHO11Signature)){
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }

        if(!(publicKey instanceof SPSAGHO11VerificationKey)){
            throw new IllegalArgumentException("Not a valid verification key for this scheme");
        }

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
        // interpret repr as list of to message block representations (one for G1 elements and one for G2 elements)
        ListRepresentation list = (ListRepresentation) repr;

        Representation g1Elements = (Representation) list.get(0);
        Representation g2Elements = (Representation) list.get(1);

        // pull the actual group elements from the representations
        MessageBlock g1 = new MessageBlock(g1Elements, r -> new GroupElementPlainText(r, pp.getG1GroupGenerator().getStructure()));
        MessageBlock g2 = new MessageBlock(g2Elements, r -> new GroupElementPlainText(r, pp.getG2GroupGenerator().getStructure()));

        return new MessageBlock(g1, g2);
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
    public MessageBlock mapToPlaintext(byte[] bytes, VerificationKey pk) {

        if(pp == null){
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }

        return mapToPlaintext(bytes, pp.getMessageLengths()[0]);
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, SigningKey sk) {

        if(pp == null){
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }

        return mapToPlaintext(bytes, pp.getMessageLengths()[0]);
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

        if(pp == null){
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }

        //TODO what?
        return (pp.getG1GroupGenerator().getStructure().size().bitLength() - 1) / 8;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }


    @Override
    public int hashCode() {
        final int prime = 41;
        int result = 1;
        result = prime * result + ((pp == null) ? 0 : pp.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if(!(o instanceof SPSAGHO11SignatureScheme))
            return false;

        SPSAGHO11SignatureScheme other = (SPSAGHO11SignatureScheme) o;

        return Objects.equals(this.pp, other.pp);

    }
}
