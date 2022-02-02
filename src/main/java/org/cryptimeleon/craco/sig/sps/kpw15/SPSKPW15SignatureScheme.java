package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11Signature;
import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11SigningKey;
import org.cryptimeleon.craco.sig.sps.agho11.SPSAGHO11VerificationKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

public class SPSKPW15SignatureScheme implements MultiMessageStructurePreservingSignatureScheme {

    /**
     * The public parameters used by the scheme
     * */
    @Represented
    SPSKPW15PublicParameters pp;

    static final int k = 2;


    public SPSKPW15SignatureScheme() { super(); }

    public SPSKPW15SignatureScheme(SPSKPW15PublicParameters pp) {
        super();
        this.pp = pp;
    }

    public SPSKPW15SignatureScheme(Representation repr) { new ReprUtil(this).deserialize(repr); }




    @Override
    public SignatureKeyPair<SPSKPW15VerificationKey, SPSKPW15SigningKey> generateKeyPair(int numberOfMessages) {

        Zp zp = pp.getZp();

        if(numberOfMessages < 1){
            throw new IllegalArgumentException(
                    "The signature scheme KPW15 expects to sign at least 1 element"
            );
        }

        // generate a,b and A,B

        ZpElement a = zp.getUniformlyRandomElement();
        ZpElement b = zp.getUniformlyRandomElement();


        ZpElementUtilMatrix A = new ZpElementUtilMatrix(2,1, zp.getOneElement(), a);
        ZpElementUtilMatrix B = new ZpElementUtilMatrix(2,1, zp.getOneElement(), b);

        // generate K (numberOfMessages x 2 matrix)

        ZpElement[] linear_K = IntStream.range(0, numberOfMessages * 2).mapToObj(
                        x -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        ZpElementUtilMatrix K = new ZpElementUtilMatrix(numberOfMessages, 2, linear_K);

        // generate K0,K1

        ZpElement[] linear_K0 = IntStream.range(0, 2 * 2).mapToObj(
                        x -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        ZpElementUtilMatrix K0 = new ZpElementUtilMatrix(2, 2, linear_K0);

        ZpElement[] linear_K1 = IntStream.range(0, 2 * 2).mapToObj(
                        x -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        ZpElementUtilMatrix K1 = new ZpElementUtilMatrix(2, 2, linear_K1);

        // calculate C, C0, C1

        ZpElementUtilMatrix C = K.mul(A);

        ZpElementUtilMatrix C0 = K0.mul(A);

        ZpElementUtilMatrix C1 = K1.mul(A);

        // calculate P0, P1

        ZpElementUtilMatrix P0 = B.mul(K0); //TODO this might need to be transposed

        ZpElementUtilMatrix P1 = B.mul(K1); //TODO this might need to be transposed

        // pack keys

        SPSKPW15SigningKey sk = new SPSKPW15SigningKey(
                K.getLinearRepresentation(),
                P0.calculateGroupElementMatrix(pp.getG1GroupGenerator()).getLinearRepresentation(),
                P1.calculateGroupElementMatrix(pp.getG1GroupGenerator()).getLinearRepresentation(),
                pp.getG1GroupGenerator().pow(b).compute()
        );

        SPSKPW15VerificationKey vk = new SPSKPW15VerificationKey(
                C0.calculateGroupElementMatrix(pp.getG2GroupGenerator()).getLinearRepresentation(),
                C1.calculateGroupElementMatrix(pp.getG2GroupGenerator()).getLinearRepresentation(),
                C.calculateGroupElementMatrix(pp.getG2GroupGenerator()).getLinearRepresentation(),
                pp.getG2GroupGenerator().pow(a).compute()
        );

        return new SignatureKeyPair<SPSKPW15VerificationKey, SPSKPW15SigningKey>(vk, sk);
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {

        if (plainText instanceof GroupElementPlainText) {
            plainText = new MessageBlock(plainText);
        }
        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        if (!(secretKey instanceof SPSKPW15SigningKey)) {
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        SPSKPW15SigningKey sk = (SPSKPW15SigningKey) secretKey;
        MessageBlock messageBlock = (MessageBlock) plainText;

        //TODO check message block length

        //pick randomness r0, r1

        ZpElement[] r0 = new ZpElement[] {  pp.getZp().getUniformlyRandomElement(),
                                            pp.getZp().getUniformlyRandomElement()
                                            };

        ZpElement r1 = pp.getZp().getUniformlyRandomElement();

        GroupElementUtilMatrix r0T = new ZpElementUtilMatrix(2, 1, r0[0], r0[1])
                .calculateGroupElementMatrix(pp.getG1GroupGenerator());

        //pull matrices from sk

        ZpElementUtilMatrix K = new ZpElementUtilMatrix(pp.messageLength, 2, sk.getK()); //TODO use k here

        GroupElementUtilMatrix P0 = new GroupElementUtilMatrix(1, 2, sk.getP0());

        GroupElementUtilMatrix P1 = new GroupElementUtilMatrix(1, 2, sk.getP1());

        //calculate sigma1

        GroupElement[] messagePadded = new GroupElement[pp.messageLength + 1];

        messagePadded[0] = pp.getG1GroupGenerator().getStructure().getNeutralElement();

        for (int i = 1; i < messagePadded.length; i++) {
            messagePadded[i] = ((GroupElementPlainText)messageBlock.get(i)).get();
        }

        GroupElementUtilMatrix mT = new GroupElementUtilMatrix(1, pp.messageLength + 1, messagePadded);

        GroupElementUtilMatrix sigma1lhs = mT.mul(K.calculateGroupElementMatrix(pp.getG1GroupGenerator()));

        GroupElementUtilMatrix sigma1rhs = r0T.mul(P0.add(P1.mul(pp.getG1GroupGenerator().pow(r1).compute())));

        GroupElementUtilMatrix sigma1mat = sigma1lhs.add(sigma1rhs);

        GroupElement[] sigma1 = (GroupElement[]) sigma1mat.getLinearRepresentation().stream().toArray();

        //calculate sigma2

        GroupElementUtilMatrix sigma2mat = r0T.mul(sk.getB());

        GroupElement[] sigma2 = (GroupElement[]) sigma2mat.getLinearRepresentation().stream().toArray();

        //calculate sigma3

        GroupElementUtilMatrix sigma3mat = sigma2mat.mul(pp.getG1GroupGenerator().pow(r1).compute()); // we can reuse sigma2 here

        GroupElement[] sigma3 = (GroupElement[]) sigma3mat.getLinearRepresentation().stream().toArray();

        //calculate sigma4

        GroupElement sigma4 = pp.getG2GroupGenerator().pow(r1).compute();

        return new SPSKPW15Signature(sigma1, sigma2, sigma3, sigma4);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {

        if(!(plainText instanceof MessageBlock)){
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }

        //TODO check message length

        if(!(signature instanceof SPSKPW15Signature)){
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }

        if(!(publicKey instanceof SPSKPW15VerificationKey)){
            throw new IllegalArgumentException("Not a valid verification key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        // we need the vector (1,m) for the PPEs
        messageBlock.prepend(new GroupElementPlainText(pp.getG1GroupGenerator().getStructure().getNeutralElement()));

        SPSKPW15Signature sigma = (SPSKPW15Signature) signature;
        SPSKPW15VerificationKey pk = (SPSKPW15VerificationKey) publicKey;

        //pull from pk

        GroupElementVector C0 = new GroupElementVector(pk.getC0());
        GroupElementVector C1 = new GroupElementVector(pk.getC1());
        GroupElementVector C = new GroupElementVector(pk.getC());

        //pull from sigma

        GroupElementVector sigma1 = new GroupElementVector(sigma.getGroup1ElementSigma1R());
        GroupElementVector sigma2 = new GroupElementVector(sigma.getGroup1ElementSigma2S());
        GroupElementVector sigma3 = new GroupElementVector(sigma.getGroup1ElementSigma3T());
        //sigma4 is only a single group element

        GroupElementVector message = messageBlock.map(x -> ((GroupElementPlainText)x).get(), GroupElementVector::new);

        return evaluateFirstPPE(sigma1, sigma2, sigma3, message, C, C0, C1, pk.getA())
                && evaluateSecondPPE(sigma2, sigma.getGroup2ElementSigma4U(), sigma3, pk.getA());
    }

    private boolean evaluateFirstPPE(GroupElementVector sigma1,
                                     GroupElementVector sigma2,
                                     GroupElementVector sigma3,
                                     GroupElementVector paddedM,
                                     GroupElementVector C,
                                     GroupElementVector C0,
                                     GroupElementVector C1,
                                     GroupElement A) {

        BilinearMap bMap = pp.getBilinearMap();
        GroupElement g2Neutral = pp.getG2GroupGenerator().getStructure().getNeutralElement();

        GroupElementVector ppe1lhs = bMap.apply(sigma1, new GroupElementVector(g2Neutral, A));

        GroupElementVector ppe1rhs1 = bMap.apply(paddedM, C).compute();
        GroupElementVector ppe1rhs2 = bMap.apply(sigma2, C0).compute();
        GroupElementVector ppe1rhs3 = bMap.apply(sigma3, C1).compute();

        GroupElementVector ppe1rhs = ppe1rhs1.op(ppe1rhs2).op(ppe1rhs3).compute();

        return ppe1lhs.equals(ppe1rhs);
    }

    private boolean evaluateSecondPPE(GroupElementVector sigma2, GroupElement sigma4, GroupElementVector sigma3, GroupElement A) {

        BilinearMap bMap = pp.getBilinearMap();
        GroupElement g2Neutral = pp.getG2GroupGenerator().getStructure().getNeutralElement();

        // apply map to linear representation of the matrices

        GroupElementVector ppe2lhs = bMap.apply((GroupElementVector) sigma2,
                new GroupElementVector(g2Neutral, A));

        ppe2lhs.compute();

        GroupElementVector ppe2rhs = bMap.apply(sigma3, new GroupElementVector(g2Neutral,g2Neutral));

        ppe2rhs.compute();

        return ppe2lhs.equals(ppe2rhs);
    }

    public SPSKPW15PublicParameters getPp(){ return pp; }


    @Override
    public MessageBlock restorePlainText(Representation repr) {
        return new MessageBlock(repr, r -> new GroupElementPlainText(r, pp.getG1GroupGenerator().getStructure()));
    }

    @Override
    public Signature restoreSignature(Representation repr) {
        return new SPSKPW15Signature(repr,
                this.pp.getG1GroupGenerator().getStructure(),
                this.pp.getG2GroupGenerator().getStructure());
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
        if(pp == null)
        {
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }
        return mapToPlaintext(bytes, pp.messageLength);
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        if(pp == null)
        {
            throw new NullPointerException("Number of messages is stored in public parameters but they are not set");
        }
        return mapToPlaintext(bytes, pp.messageLength);
    }

    private MessageBlock mapToPlaintext(byte[] bytes, int messageLength) {
        // returns (P^m, P, ..., P) where m = Z_p.injectiveValueOf(bytes).

        GroupElementPlainText[] msgBlock = new GroupElementPlainText[messageLength];
        msgBlock[0] = new GroupElementPlainText(
                pp.getG1GroupGenerator().pow(pp.getZp().injectiveValueOf(bytes))
        );
        for (int i = 1; i < msgBlock.length; i++) {
            msgBlock[i] = new GroupElementPlainText(pp.getG1GroupGenerator());
        }

        return new MessageBlock(msgBlock);
    }


    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getG1GroupGenerator().getStructure().size().bitLength() - 1) / 8;
    }

    @Override
    public Representation getRepresentation() { return ReprUtil.serialize(this); }


    @Override
    public int hashCode() {
        final int prime = 41;
        int result = 1;
        result = prime * result + ((pp == null) ? 0 : pp.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if(!(o instanceof SPSKPW15SignatureScheme))
            return false;

        SPSKPW15SignatureScheme other = (SPSKPW15SignatureScheme) o;

        return Objects.equals(this.pp, other.pp);
    }

}
