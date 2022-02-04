package org.cryptimeleon.craco.sig.sps.kpw15;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.RingElement;
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

    static final int k = 1;


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

        // generate A,B (2 x 1 matrices)

        ZpElement[] A = new ZpElement[]{zp.getOneElement(), zp.getUniformlyRandomElement()}; // A: 2x1
        ZpElement[] B = new ZpElement[]{zp.getOneElement(), zp.getUniformlyRandomElement()}; // B: 2x1

        // generate K ((n + 1) x 2 matrix)

        ZpElement[] K = IntStream.range(0, (numberOfMessages + 1) * 2).mapToObj(
                        x -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        // generate K0,K1 (2 x 2 matrices)

        ZpElement[] K0 = IntStream.range(0, 2 * 2).mapToObj(
                        x -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        ZpElement[] K1 = IntStream.range(0, 2 * 2).mapToObj(
                        x -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        // calculate C ((n+1) x 1)

        ZpElement[] C = MatrixUtility.matrixMul(
                K, (numberOfMessages + 1), 2,
                A, 2, 1); //K.mul(A)

        // calculate C0, C1 (2 x 1)

        ZpElement[] C0 = MatrixUtility.matrixMul(
                K0, 2, 2,
                A, 2, 1); //K0.mul(A)

        ZpElement[] C1 = MatrixUtility.matrixMul(
                K1, 2, 2,
                A, 2, 1);//K1.mul(A)

        // calculate P0, P1 (1 x 2)

        //Note that we transpose B implicitly, as it only contains 2 elements anyway
        ZpElement[] P0 = MatrixUtility.matrixMul(
                B, 1, 2,
                K0, 2, 2
        ); //BT.mul(K0)

        ZpElement[] P1 = MatrixUtility.matrixMul(
                B, 1, 2,
                K1, 2, 2
        ); //BT.mul(K1)

        // pack keys

        SPSKPW15SigningKey sk = new SPSKPW15SigningKey(
                K,
                pp.getG1GroupGenerator().pow(new Vector<ZpElement>(P0)).compute().stream().toArray(GroupElement[]::new),
                pp.getG1GroupGenerator().pow(new Vector<ZpElement>(P1)).compute().stream().toArray(GroupElement[]::new),
                pp.getG1GroupGenerator().pow(B[1]).compute()
        );

        SPSKPW15VerificationKey vk = new SPSKPW15VerificationKey(
                pp.getG2GroupGenerator().pow(new Vector<ZpElement>(C0)).compute().stream().toArray(GroupElement[]::new),
                pp.getG2GroupGenerator().pow(new Vector<ZpElement>(C1)).compute().stream().toArray(GroupElement[]::new),
                pp.getG2GroupGenerator().pow(new Vector<ZpElement>(C)).compute().stream().toArray(GroupElement[]::new),
                pp.getG2GroupGenerator().pow(A[1]).compute()
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
        messageBlock.prepend(new GroupElementPlainText(pp.getG1GroupGenerator()));

        //TODO check message block length

        //pick randomness r0, r1

        ZpElement r0 = pp.getZp().getUniformlyRandomElement();

        ZpElement r1 = pp.getZp().getUniformlyRandomElement();


        //calculate sigma1 (1 x 2 matrix)

        GroupElement[] message = new GroupElement[messageBlock.length()+1];

        message[0] = pp.getG1GroupGenerator();

        for (int i = 1; i <= messageBlock.length(); i++) {
            message[i] = ((GroupElementPlainText) messageBlock.get(i-1)).get();
        }

        GroupElement[] sigma1lhs = MatrixUtility.calculateSigma1Matrix(message, sk.getK());

        GroupElement[] sigma1rhsInner = Arrays.stream(sk.getP1()).map(
                x -> x.pow(r1).compute()
        ).toArray(GroupElement[]::new);

        for (int i = 0; i < sigma1rhsInner.length; i++) {
            sigma1rhsInner[i] = sk.getP0()[i].op(sigma1rhsInner[i]);
            sigma1rhsInner[i] = sigma1rhsInner[i].pow(r0);
            sigma1rhsInner[i].compute();
        }

        GroupElement[] sigma1 = new GroupElement[sigma1lhs.length];

        for (int i = 0; i < sigma1.length; i++) {
            sigma1[i] = sigma1lhs[i].op(sigma1rhsInner[i]).compute();
        }


        //calculate sigma2 (1 x 2 matrix)

        GroupElement[] sigma2 = new Vector<GroupElement>(pp.getG1GroupGenerator(), sk.getB()).stream().map(
                x -> x.pow(r0).compute()
        ).toArray(GroupElement[]::new);

        //calculate sigma3 ( 1 x 2 matrix)

        GroupElement[] sigma3 = Arrays.stream(sigma2).map(
                x -> x.pow(r1)
        ).toArray(GroupElement[]::new);

        //calculate sigma4 (single element)

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
        GroupElement[] message = new GroupElement[messageBlock.length()+1];

        message[0] = pp.getG1GroupGenerator();

        for (int i = 1; i <= messageBlock.length(); i++) {
            message[i] = ((GroupElementPlainText) messageBlock.get(i-1)).get();
        }


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


        return evaluateFirstPPE(sigma1, sigma2, sigma3, message, C, C0, C1, pk.getA())
                && evaluateSecondPPE(sigma2, sigma.getGroup2ElementSigma4U(), sigma3);
    }

    private boolean evaluateFirstPPE(GroupElementVector sigma1,
                                     GroupElementVector sigma2,
                                     GroupElementVector sigma3,
                                     GroupElement[] message,
                                     GroupElementVector C,
                                     GroupElementVector C0,
                                     GroupElementVector C1,
                                     GroupElement A) {

        BilinearMap bMap = pp.getBilinearMap();

        //for matrices, Kiltz et al. define e(A,B) = AxB
        //note how these all result in a 1x1 matrix / a single group element

        GroupElementVector ppe1lhs = MatrixUtility.matrixMul(
                bMap,
                sigma1, 1, 2,
                new GroupElementVector(pp.getG2GroupGenerator(), A), 2, 1
                ).compute();


        GroupElementVector ppe1rhs1 = MatrixUtility.matrixMul(
                bMap,
                new GroupElementVector(message), 1, message.length,
                C, message.length, 1);

        GroupElementVector ppe1rhs2 = MatrixUtility.matrixMul(
                bMap,
                sigma2, 1, 2,
                C0, 2, 1);

        GroupElementVector ppe1rhs3 = MatrixUtility.matrixMul(bMap,
                sigma3, 1, 2,
                C1, 2, 1);

        GroupElementVector ppe1rhs = ppe1rhs1.op(ppe1rhs2).op(ppe1rhs3).compute();

        return ppe1lhs.equals(ppe1rhs);
    }

    private boolean evaluateSecondPPE(GroupElementVector sigma2, GroupElement sigma4, GroupElementVector sigma3) {

        BilinearMap bMap = pp.getBilinearMap();

        GroupElementVector ppe2lhs = MatrixUtility.matrixMul(
                bMap,
                sigma2, 1, 2,
                new GroupElementVector(sigma4, sigma4), 2, 1
                ); //TODO optimize

        GroupElementVector ppe2rhs = MatrixUtility.matrixMul(
                bMap,
                sigma3, 1, 2,
                new GroupElementVector(pp.getG2GroupGenerator(), pp.getG2GroupGenerator()), 2, 1
                );

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
        return new SPSKPW15SigningKey(repr, this.pp.getZp(), pp.getG1GroupGenerator().getStructure());
    }

    @Override
    public VerificationKey restoreVerificationKey(Representation repr) {
        return new SPSKPW15VerificationKey(this.pp.getG1GroupGenerator().getStructure(),
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
