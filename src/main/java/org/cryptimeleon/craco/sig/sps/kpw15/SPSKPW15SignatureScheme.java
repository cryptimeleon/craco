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
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

/**
 * A simplified implementation of the SPS scheme originally presented in [1] by Kiltz et al. as seen in [2]
 * Signs a vector of {n} group elements in G_1.
 *
 * This simplification is achieved by setting the parameter "k" in the paper to the fixed value of 1.
 * Consequently, this simplified scheme is secure under the SXDH assumption [1 , p. 3]
 *
 * <p>
 * Bilinear map type: 3
 * <p>
 *
 * [1] Kiltz, E.,Pan, J., Wee, H.:
 * Structure-Preserving Signatures from Standard Assumptions, Revisited
 * https://eprint.iacr.org/2015/604.pdf
 *
 * [2] Sakai, Y., Attrapadung, N., Hanaoka, G.:
 * Attribute-Based Signatures for Circuits from Bilinear Map
 * https://eprint.iacr.org/2016/242.pdf
 */
public class SPSKPW15SignatureScheme implements MultiMessageStructurePreservingSignatureScheme {

    /**
     * The public parameters used by the scheme
     */
    @Represented
    SPSKPW15PublicParameters pp;

    /**
     * Performs a limited set of matrix operations required by the KPW15 SPS scheme.
     */
    static class MatrixUtility {

        /**
         * Interpret two arrays of {@link ZpElement}s as matrices and multiply them
         */
        public static ZpElement[] matrixMul(ZpElement[] A, int rowsA, int columnsA,
                                            ZpElement[] B, int rowsB, int columnsB) {
            //check if matrices can be multiplied
            if(A.length != rowsA * columnsA || B.length != rowsB * columnsB) {
                throw new IllegalArgumentException("The given vector's length does not match its matrix dimensions" );
            }

            if(columnsA != rowsB) {
                throw new IllegalArgumentException(
                        String.format("function is only defined for matrices where columns_A == rows_B : got %d vs. %d",
                                columnsA,
                                rowsB)
                );
            }

            ZpElement[] multiplied = new ZpElement[rowsA * columnsB];

            // calculate the individual elements

            for (int r = 1; r <= rowsA; r++) {
                for (int c = 1; c <= columnsB; c++) {

                    ZpElement value = B[0].getStructure().getZeroElement();

                    for (int i = 1; i <= columnsA; i++) {
                        value = value.add(
                                A[getMatrixIndex(rowsA, columnsA, r, i)].mul(B[getMatrixIndex(rowsB, columnsB, i, c)]));
                    }

                    multiplied[getMatrixIndex(rowsA, columnsB, r,c)] = value;
                }
            }

            return multiplied;
        }

        /**
         * Kiltz et al. define e(A,B) for two matrices as AxB.
         * We apply the bilinear map to each row/column in order to calculate the result.
         */
        public static GroupElementVector matrixApplyMap(BilinearMap bMap,
                                                        GroupElementVector A, int rowsA, int columnsA,
                                                        GroupElementVector B, int rowsB, int columnsB) {
            //check if matrices can be multiplied
            if(A.length() != rowsA * columnsA || B.length() != rowsB * columnsB) {
                throw new IllegalArgumentException("The given vectors length does not match its matrix dimensions");
            }

            if(columnsA != rowsB) {
                throw new IllegalArgumentException(
                        String.format("function is only defined for matrices where columns_A == rows_B : got %d x %d",
                                columnsA,
                                rowsB)
                );
            }

            GroupElement[] multiplied = new GroupElement[rowsA * columnsB];

            // now, calculate the individual elements

            for (int r = 1; r <= rowsA; r++) {
                for (int c = 1; c <= columnsB; c++) {

                    GroupElement value = bMap.getGT().getNeutralElement();

                    for (int i = 1; i <= columnsA; i++) {
                        value = value.op(
                                bMap.apply(A.get(getMatrixIndex(rowsA, columnsA, r, i)),
                                        B.get(getMatrixIndex(rowsB, columnsB, i, c))
                                )
                        );
                    }

                    value.compute();
                    multiplied[getMatrixIndex(rowsA, columnsB, r,c)] = value;
                }
            }

            return new GroupElementVector(multiplied);
        }

        /**
         * Calculate a linear index for the given matrix position
         */
        public static int getMatrixIndex(int rows, int columns, int row, int column)
        {
            return (rows * (column - 1)) + (row - 1);
        }


        /**
         * Utility method that calculates e((1,m),K) as specified in the signing function.
         */
        public static GroupElement[] calculateSigma1MatrixMxK(GroupElement[] message, ZpElement[] K) {

            // multiplying message(1 x n+1 matrix) and K(n+1 x 2 matrix) results in a 1 x 2 matrix

            int rows = 1;
            int columns = 2;

            GroupElement[] multiplied = new GroupElement[rows * columns];

            for (int c = 1; c <= columns; c++) {
                GroupElement value = message[0].getStructure().getNeutralElement();

                for (int i = 1; i <= message.length; i++) {

                    // we may multiply here because K is in Zp. This would not work for two GroupElement matrices
                    ZpElement exponentK = K[getMatrixIndex(message.length, 2, i, c)];
                    GroupElement messageElement = message[i - 1];

                    value = value.op(messageElement.pow(exponentK));
                }

                value.compute();
                multiplied[c-1] = value;
            }

            return multiplied;
        }

    }


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

        // calculate C ((n+1) x 1 matrix)

        ZpElement[] C = MatrixUtility.matrixMul(
                K, (numberOfMessages + 1), 2,
                A, 2, 1); //K.mul(A)

        // calculate C0, C1 (2 x 1 matrix)

        ZpElement[] C0 = MatrixUtility.matrixMul(
                K0, 2, 2,
                A, 2, 1); //K0.mul(A)

        ZpElement[] C1 = MatrixUtility.matrixMul(
                K1, 2, 2,
                A, 2, 1); //K1.mul(A)

        // calculate P0, P1 (1 x 2)

        //Note that we transpose B implicitly here, as it only contains 2 elements anyway
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

        if((plainText instanceof GroupElementPlainText)){
            plainText = new MessageBlock(plainText); //if only a single element was given, wrap it in a MessageBlock
        }

        // check if the plainText matches the structure required by the scheme
        doMessageChecks(plainText);

        MessageBlock messageBlock = (MessageBlock) plainText;
        messageBlock.prepend(new GroupElementPlainText(pp.getG1GroupGenerator()));

        if (!(secretKey instanceof SPSKPW15SigningKey)) {
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        SPSKPW15SigningKey sk = (SPSKPW15SigningKey) secretKey;

        //pick randomness r0, r1

        ZpElement r0 = pp.getZp().getUniformlyRandomElement();

        ZpElement r1 = pp.getZp().getUniformlyRandomElement();


        //calculate sigma1 (1 x 2 matrix)

        GroupElement[] message = new GroupElement[messageBlock.length()+1];

        message[0] = pp.getG1GroupGenerator();

        for (int i = 1; i <= messageBlock.length(); i++) {
            message[i] = ((GroupElementPlainText) messageBlock.get(i-1)).get();
        }

        GroupElement[] sigma1lhs = MatrixUtility.calculateSigma1MatrixMxK(message, sk.getK());

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

        //System.out.println("check sigma1: " + checkSigma1(sigma1, message, sk.getK(), r0, r1, sk.getP0(), sk.getP1()));

        return new SPSKPW15Signature(sigma1, sigma2, sigma3, sigma4);
    }

    private boolean checkSigma1(GroupElement[] sigma1,
                                GroupElement[] paddedMessage,
                                ZpElement[] K,
                                ZpElement r0, ZpElement r1,
                                GroupElement[] P0, GroupElement[] P1 ) {

        // n = 1
        // padded message^T (1 x 2) x K (2 x 2) -> 1 x 2

        GroupElement[] lhs = new GroupElement[1 * 2];

        lhs[0] = paddedMessage[0].pow(K[0]).op(paddedMessage[1].pow(K[1])).compute();
        lhs[1] = paddedMessage[0].pow(K[2]).op(paddedMessage[1].pow(K[3])).compute();

        // r0 (P0 + r1 * P1)

        GroupElement[] r1P1 = new GroupElement[1 * 2];

        r1P1[0] = P1[0].pow(r1).compute();
        r1P1[1] = P1[1].pow(r1).compute();

        GroupElement[] P0r1P1 = new GroupElement[2];

        P0r1P1[0] = P0[0].op(r1P1[0]).compute();
        P0r1P1[1] = P0[1].op(r1P1[1]).compute();

        GroupElement[] rhs = new GroupElement[2];

        rhs[0] = P0r1P1[0].pow(r0).compute();
        rhs[1] = P0r1P1[1].pow(r0).compute();

        GroupElement[] checkSig = new GroupElement[2];

        checkSig[0] = lhs[0].op(rhs[0]).compute();
        checkSig[1] = lhs[1].op(rhs[1]).compute();


        return sigma1[0].equals(checkSig[0]) && sigma1[1].equals(checkSig[1]);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {

        if((plainText instanceof GroupElementPlainText)){
            plainText = new MessageBlock(plainText); //if only a single element was given, wrap it in a MessageBlock
        }

        // check if the plainText matches the structure required by the scheme
        doMessageChecks(plainText);

        if(!(signature instanceof SPSKPW15Signature)){
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }

        if(!(publicKey instanceof SPSKPW15VerificationKey)){
            throw new IllegalArgumentException("Not a valid verification key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        // we need the vector (1,m) for the PPEs
        messageBlock = padMessage(messageBlock);

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


        return evaluateFirstPPE(sigma1, sigma2, sigma3, messageBlock, C, C0, C1, pk.getA())
                && evaluateSecondPPE(sigma2, sigma.getGroup2ElementSigma4U(), sigma3);
    }


    /**
     * Evaluates the first PPE as defined in the paper.
     */
    private boolean evaluateFirstPPE(GroupElementVector sigma1,
                                     GroupElementVector sigma2,
                                     GroupElementVector sigma3,
                                     MessageBlock paddedMessage,
                                     GroupElementVector C,
                                     GroupElementVector C0,
                                     GroupElementVector C1,
                                     GroupElement A) {

        BilinearMap bMap = pp.getBilinearMap();

        GroupElement[] message = paddedMessage.stream().map(
                x->((GroupElementPlainText)x).get()
        ).toArray(GroupElement[]::new);

        //for matrices, Kiltz et al. define e(A,B) = AxB
        //note how these all result in a 1x1 matrix / a single group element

        GroupElementVector ppe1lhs = MatrixUtility.matrixApplyMap(
                bMap,
                sigma1, 1, 2,
                new GroupElementVector(pp.getG2GroupGenerator(), A), 2, 1
                ).compute();

        GroupElementVector ppe1rhs1 = MatrixUtility.matrixApplyMap(
                bMap,
                new GroupElementVector(message), 1, message.length,
                C, message.length, 1);

        GroupElementVector ppe1rhs2 = MatrixUtility.matrixApplyMap(
                bMap,
                sigma2, 1, 2,
                C0, 2, 1);

        GroupElementVector ppe1rhs3 = MatrixUtility.matrixApplyMap(bMap,
                sigma3, 1, 2,
                C1, 2, 1);

        GroupElementVector ppe1rhs = ppe1rhs1.op(ppe1rhs2).op(ppe1rhs3).compute();

        return ppe1lhs.equals(ppe1rhs);
    }

    /**
     * Evaluates the second PPE as defined in the paper.
     */
    private boolean evaluateSecondPPE(GroupElementVector sigma2, GroupElement sigma4, GroupElementVector sigma3) {

        BilinearMap bMap = pp.getBilinearMap();

        GroupElementVector ppe2lhs = MatrixUtility.matrixApplyMap(
                bMap,
                sigma2, 1, 2,
                new GroupElementVector(sigma4, sigma4), 2, 1
                );

        GroupElementVector ppe2rhs = MatrixUtility.matrixApplyMap(
                bMap,
                sigma3, 1, 2,
                new GroupElementVector(pp.getG2GroupGenerator(), pp.getG2GroupGenerator()), 2, 1
                );

        return ppe2lhs.equals(ppe2rhs);
    }

    /**
     * Messages given to this scheme must be padded with one instance of the G_1 generator set in the public parameters.
     * This is required in order for the dimensions of the message and matrices to match.
     */
    private MessageBlock padMessage(MessageBlock messageBlock) {
        return new MessageBlock(
                messageBlock.prepend(
                        new GroupElementPlainText(pp.getG1GroupGenerator())
                )
        );
    }

    /**
     * Check if the given plainText matches the structure expected by the scheme
     *      and throws detailed exception if the plainText fails any check.
     *      The scheme expects messages containing a vector of{@link GroupElementPlainText}s in G_1.
     *      Size must match the public parameters.
     * */
    private void doMessageChecks(PlainText plainText) {

        MessageBlock messageBlock;

        // The scheme expects a MessageBlock...
        if(plainText instanceof MessageBlock) {
            messageBlock = (MessageBlock) plainText;
        }
        else {
            throw new IllegalArgumentException("The scheme requires its messages to be GroupElements");
        }

        // ...with a size matching the public parameters...
        if(messageBlock.length() != pp.messageLength) {
            throw new IllegalArgumentException(String.format(
                    "The scheme expected a message of length %d, but the size was: %d",
                    pp.messageLength, messageBlock.length()
            ));
        }

        // ...containing group elements...
        for (int i = 0; i < messageBlock.length(); i++) {
            if(!(messageBlock.get(i) instanceof GroupElementPlainText)) {
                throw new IllegalArgumentException(
                        String.format(
                                "The scheme requires its messages to be GroupElements," +
                                        " but element %d was of type: %s",
                                i, messageBlock.get(i).getClass().toString()
                        )
                );
            }

            // ... in G1.
            GroupElementPlainText groupElementPT = (GroupElementPlainText) messageBlock.get(i);
            if(!(groupElementPT.get().getStructure().equals(pp.getG1GroupGenerator().getStructure()))) {
                throw new IllegalArgumentException(
                        String.format(
                                "Expected message to be in G_1, but element %d was in: %s",
                                i, groupElementPT.get().getStructure().toString()
                        )
                );
            }
        }

        // if no exception has been thrown at this point, we can assume the message matches the expected structure.
    }


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
