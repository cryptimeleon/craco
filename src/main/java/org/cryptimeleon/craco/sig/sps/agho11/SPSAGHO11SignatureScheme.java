package org.cryptimeleon.craco.sig.sps.agho11;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

/**
 * An implementation of the scheme originally presented in [1]
 *
 * [1] Abe et. al.: Optimal Structure-Preserving Signatures in Asymmetric Bilinear Groups.
 * CRYPTO 2011: Advances in Cryptology – CRYPTO 2011 pp. 649-666
 * https://www.iacr.org/archive/crypto2011/68410646/68410646.pdf
 *
 * Note: To ensure the scheme's security as described in [1], messages and keys will be padded to length
 *      for short messages (k_M = 0 or k_N \in {0,1}), such that at least one G_1 group element and
 *      at least two G_2 groupElements are signed.
 *      The messages are assumed to be composed of a tuple of two {@link MessageBlock}s;
 *      one containing {@link  GroupElementPlainText}s of elements in G_1 and the other {@link  GroupElementPlainText}s
 *      of elements in G_2.
 *      The message vectors are padded with the neutral element of they respective groups.
 *      The key generation function accounts for this edge-case automatically by calculating the extra elements
 *      that are required as a consequence of the padding.
 *      From a user perspective, any positive length tuple of two message-vectors (M \in G_1,N \in G_2) may be passed
 *      without the need for additional precautions.
 *
 */
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
    public SignatureKeyPair<SPSAGHO11VerificationKey, SPSAGHO11SigningKey> generateKeyPair(int numberOfMessages)
    {
        return generateKeyPair(numberOfMessages, 2);
    }

    /**
     * Generates a key pair for signing n blocks of messages with {@code  messageBlockLengths}
     * with each signature.
     *
     * @param messageBlockLengths the length of the individual MessageBlocks this scheme accepts as input.
     */
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
                throw new IllegalArgumentException(
                        String.format(
                                "The given message length of the %s vector does not match the public parameters" +
                                " expected: %d, but was: %d",
                                (i == 0) ? "first" : "second",
                                pp.getMessageLengths()[i],
                                messageBlockLengths[i]
                        )
                );
            }
        }

        // edge-case: if the expected messageBlockLengths are too short, add padding to the key
        int firstMsgVectorLength = Math.max(1, messageBlockLengths[0]); // k_M will be padded to be at least 1
        int secondMsgVectorLength = Math.max(2, messageBlockLengths[1]); // k_N will be padded to be at least 2

        ZpElement[] exponentsU = IntStream.range(0, secondMsgVectorLength).mapToObj( //note that u_1 ... u_k_N
                x -> zp.getUniformlyRandomNonzeroElement())
                .toArray(ZpElement[]::new);
        ZpElement[] exponentsW = IntStream.range(0, firstMsgVectorLength).mapToObj( //and that w_1 ... w_k_M
                x -> zp.getUniformlyRandomNonzeroElement())
                .toArray(ZpElement[]::new);

        Zp.ZpElement exponentV = zp.getUniformlyRandomNonzeroElement();
        Zp.ZpElement exponentZ = zp.getUniformlyRandomNonzeroElement();

        // Calculate Vectors for public key
        GroupElement[] groupElementsU = Arrays.stream(exponentsU).map(
                x -> pp.getG1GroupGenerator().pow(x).compute())
                .toArray(GroupElement[]::new);
        GroupElement[] groupElementsW = Arrays.stream(exponentsW).map(
                x -> pp.getG2GroupGenerator().pow(x).compute())
                .toArray(GroupElement[]::new);

        // Create public key (verification key)
        SPSAGHO11VerificationKey pk = new SPSAGHO11VerificationKey(
                groupElementsU,
                pp.getG2GroupGenerator().pow(exponentV).compute(),
                groupElementsW,
                pp.getG2GroupGenerator().pow(exponentZ).compute()
        );

        // Create secret key (signing key)
        SPSAGHO11SigningKey sk = new SPSAGHO11SigningKey(exponentsU, exponentV, exponentsW, exponentZ);

        return new SignatureKeyPair<>(pk, sk);
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {

        // check if the plainText matches the expected message structure
        // the scheme signs messages on G^(k_M) x H^(k_N), so we need a MessageBlock containing 2 MessageBlocks
        doMessageChecks(plainText);

        if(!(secretKey instanceof SPSAGHO11SigningKey)){
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        MessageBlock containerBlock = (MessageBlock) plainText;
        containerBlock = padMessageIfShort(containerBlock); // pad message if necessary

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

        GroupElement sigma2S = sigma2S1.op(sigma2S2).compute();

        GroupElement sigma3T = pp.getG2GroupGenerator().getStructure().getNeutralElement();
        for (int i = 0; i < k_N; i++) {
            sigma3T = sigma3T.op(
                    ((GroupElementPlainText) messageHElements.get(i)).get() // N_i
                            .pow(sk.getExponentsU()[i].neg()) // ^(-u_i)
            );
        }
        sigma3T = sigma3T.op(pp.getG2GroupGenerator()); // * H
        sigma3T = sigma3T.pow(r.inv()).compute(); // ^1/r

        return new SPSAGHO11Signature(sigma1R, sigma2S, sigma3T);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {

        // check if the plainText matches the expected message structure
        // the scheme signs messages on G^(k_M) x H^(k_N), so we need a MessageBlock containing 2 MessageBlocks
        doMessageChecks(plainText);

        if(!(signature instanceof SPSAGHO11Signature)){
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }

        if(!(publicKey instanceof SPSAGHO11VerificationKey)){
            throw new IllegalArgumentException("Not a valid verification key for this scheme");
        }

        MessageBlock containerBlock = (MessageBlock) plainText;
        containerBlock = padMessageIfShort(containerBlock); // pad message if necessary

        MessageBlock messageGElements = (MessageBlock) containerBlock.get(0);
        MessageBlock messageHElements = (MessageBlock) containerBlock.get(1);


        SPSAGHO11Signature sigma = (SPSAGHO11Signature) signature;
        SPSAGHO11VerificationKey pk = (SPSAGHO11VerificationKey) publicKey;

        return evaluateFirstPPE(messageGElements, sigma, pk)
                && evaluateSecondPPE(messageHElements, sigma, pk);
    }

    /**
     * Checks if the given combination of message, key and signature create a valid pairing product equation
     *      in regard to the scheme's first PPE defined in the paper.
     */
    private boolean evaluateFirstPPE(MessageBlock messageBlock, SPSAGHO11Signature sigma, SPSAGHO11VerificationKey pk){

        BilinearMap bMap = pp.getBilinearMap();

        //left-hand side
        GroupElement lhs1 = bMap.apply(sigma.getGroup1ElementSigma1R(), pk.getGroup2ElementV());
        lhs1 = lhs1.op(bMap.apply(sigma.getGroup1ElementSigma2S(), pp.getG2GroupGenerator()));

        GroupElement lhs2 = pp.getGT().getNeutralElement();

        for (int i = 0; i < messageBlock.length(); i++) {
            lhs2 = lhs2.op(
                    bMap.apply(((GroupElementPlainText)messageBlock.get(i)).get(), pk.getGroup2ElementsW()[i])
            );
        }

        GroupElement lhs = lhs1.op(lhs2);
        lhs.compute();

        // right-hand side
        GroupElement rhs = bMap.apply(pp.getG1GroupGenerator(), pk.getGroup2ElementZ());
        rhs.compute();

        return lhs.equals(rhs);
    }

    /**
     * Checks if the given combination of message, key and signature create a valid pairing product equation
     *      in regard to the scheme's second PPE defined in the paper.
     */
    private boolean evaluateSecondPPE(MessageBlock messageBlock, SPSAGHO11Signature sigma, SPSAGHO11VerificationKey pk){

        BilinearMap bMap = pp.getBilinearMap();

        //left-hand side
        GroupElement lhs1 = bMap.apply(sigma.getGroup1ElementSigma1R(), sigma.getGroup2ElementSigma3T());

        GroupElement lhs2 = pp.getGT().getNeutralElement();

        for (int i = 0; i < messageBlock.length(); i++) {
            lhs2 = lhs2.op(
                    bMap.apply(pk.getGroup1ElementsU()[i], ((GroupElementPlainText)messageBlock.get(i)).get())
            );
        }

        GroupElement lhs = lhs1.op(lhs2).compute();

        //right-hand side
        GroupElement rhs = bMap.apply(pp.getG1GroupGenerator(), pp.getG2GroupGenerator()).compute();

        return lhs.equals(rhs);
    }

    @Override
    public PlainText restorePlainText(Representation repr) {
        // interpret repr as list of to message block representations (one for G1 elements and one for G2 elements)
        ListRepresentation list = (ListRepresentation) repr;

        Representation g1Elements = (Representation) list.get(0);
        Representation g2Elements = (Representation) list.get(1);

        // pull the actual group elements from the representations
        MessageBlock g1 = new MessageBlock(
                g1Elements, r -> new GroupElementPlainText(r, pp.getG1GroupGenerator().getStructure())
        );
        MessageBlock g2 = new MessageBlock(
                g2Elements, r -> new GroupElementPlainText(r, pp.getG2GroupGenerator().getStructure())
        );

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

        // if the scheme uses zero length messages for G1, messages will be padded to at least 1 element
        if(messageBlockLength == 0) {
            messageBlockLength = 1;
        }

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

    /**
     * Checks if the given {@link PlainText} matches the structure expected by the scheme and
     *      throws detailed exception if the plainText fails any check.
     *      The scheme expects a {@link MessageBlock} with two inner {@link MessageBlock}s, each holding
     *      {@link GroupElementPlainText}s in G1 and G2 respectively.
     */
    private void doMessageChecks(PlainText plainText) throws IllegalArgumentException{

        // check if the plainText is a MessageBlock...
        if(!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException(
                    String.format("The plainText provided must be a MessageBlock, but was: %s",
                    plainText.getClass().toString()
                    )
            );
        }

        MessageBlock msgBlock = (MessageBlock) plainText;

        // ...with two inner elements...
        if(msgBlock.length() != 2) {
            throw new IllegalArgumentException(
                    String.format("The message provided must contain 2 inner MessageBlocks, but had: %d",
                            msgBlock.length()
                    )
            );
        }

        // ...that are messageBlocks...
        for (int i = 0; i < 2; i++) {
            if(!(msgBlock.get(i) instanceof MessageBlock)) {
                throw new IllegalArgumentException(
                        String.format(
                                "The message provided must contain 2 inner MessageBlocks," +
                                        " but element %d was not an instance of MessageBlock", i));
            }
        }

        // test both inner message blocks
        MessageBlock innerBlock1 = (MessageBlock) msgBlock.get(0);
        MessageBlock innerBlock2 = (MessageBlock) msgBlock.get(1);

        for (int blockID = 0; blockID < 2; blockID++) {
            MessageBlock innerBlock = (blockID == 0) ? innerBlock1 : innerBlock2;
            int expectedLength = pp.messageLengths[blockID];
            Group expectedGroup =
                    (blockID == 0) ? pp.getG1GroupGenerator().getStructure() : pp.getG2GroupGenerator().getStructure();

            // ...whose lengths match those defined in the public parameters...
            if(innerBlock.length() != expectedLength) {
                throw new IllegalArgumentException(
                        String.format(
                                "length of %s message vector does not match public parameters" +
                                        " expected %d, but was: %d",
                                (blockID == 0) ? "first" : "second",
                                innerBlock1.length(), pp.messageLengths[0]
                        )
                );
            }

            // ...and hold GroupElementPlainTexts in G1 and G2 respectively...
            for (int i = 0; i < innerBlock.length(); i++) {
                if(!(innerBlock.get(i) instanceof GroupElementPlainText)) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "The inner message blocks may only contain GroupElementPlainTexts," +
                                            " but element %d of inner block %d was of type: %s",
                                    i,
                                    blockID,
                                    innerBlock.get(i).getClass().toString()
                                    )
                    );
                }

                GroupElement groupElement = ((GroupElementPlainText)innerBlock.get(i)).get();

                if(!(groupElement.getStructure().equals(expectedGroup))) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "Element %d of inner message block %d does not match the expected group. "
                                    + " expected: %s, but was: %s",
                                    i,
                                    blockID,
                                    groupElement.getStructure().toString(),
                                    expectedGroup.toString()
                            )
                    );
                }
            }
        }

        // if no exception has been thrown at this point, we can assume the message matches the expected structure.
    }

    /**
     * Pads a given {@link MessageBlock} in case either of its inner MessageBlocks is too short.
     * k_M (the first inner Block) must be at least 1 element long
     * k_N (the second inner Block) must be at least 2 elements long
     */
    private MessageBlock padMessageIfShort(MessageBlock messageBlock) {

        // at this point we assume the message is of the correct structure, as per {@code doMessageChecks()}

        MessageBlock firstInnerBlock = (MessageBlock) messageBlock.get(0);
        MessageBlock secondInnerBlock = (MessageBlock) messageBlock.get(1);

        GroupElement g1Neutral = pp.getG1GroupGenerator().getStructure().getNeutralElement();
        GroupElement g2Neutral = pp.getG2GroupGenerator().getStructure().getNeutralElement();

        //pad messages only if needed
        if(pp.getMessageLengths()[0] < 1) {
            firstInnerBlock = new MessageBlock(
                    firstInnerBlock.pad(new GroupElementPlainText(g1Neutral), 1)
            );
        }

        if(pp.getMessageLengths()[1] < 2) {
            secondInnerBlock = new MessageBlock(
                    secondInnerBlock.pad(new GroupElementPlainText(g2Neutral), 2)
            );
        }

        return new MessageBlock(firstInnerBlock, secondInnerBlock);
    }
    
}
