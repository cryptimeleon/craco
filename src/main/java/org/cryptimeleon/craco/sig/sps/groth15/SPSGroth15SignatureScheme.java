package org.cryptimeleon.craco.sig.sps.groth15;

import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Objects;
import java.util.stream.IntStream;

/**
 * Signature scheme that was originally presented in [1] by Groth for signing matrices.
 * This is the simplified version for vectors of messages from G_1 or G_2 as presented in [2].
 * A version for messages in G_2 can be obtained by swapping membership of all elements and vice versa.
 * <p>
 * Bilinear map type: 3
 * <p>
 * [1] Groth, J.: Efficient fully structure-preserving signatures for large messages.
 * ASIACRYPT 2015, Part I. LNCS, vol. 9452, pp. 239–259. Springer, Heidelberg
 * https://eprint.iacr.org/2015/824.pdf
 * <p>
 * [2] Camenisch, J., Drijvers, M., Dubovitskaya, M.:
 * Practical UC-secure delegatable credentials with attributes and their application to blockchain.
 * ACM CCS 2017. pp. 683–699. ACM Press
 */

public class SPSGroth15SignatureScheme implements MultiMessageStructurePreservingSignatureScheme {

    /**
     * Public parameters of the signature scheme.
     */
    @Represented
    protected SPSGroth15PublicParameters pp;

    protected SPSGroth15SignatureScheme() {
        super();
    }

    public SPSGroth15SignatureScheme(SPSGroth15PublicParameters pp) {
        super();
        this.pp = pp;
    }

    public SPSGroth15SignatureScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public SignatureKeyPair<SPSGroth15VerificationKey, SPSGroth15SigningKey> generateKeyPair(int numberOfMessages) {
        // Do actual key generation (cf. KeyGen algorithm)
        Zp zp = pp.getZp();
        GroupElement plaintextGroupElement = pp.getPlaintextGroupGenerator();

        // check if number of messages l > 0
        if (!(numberOfMessages > 0)) {
            throw new IllegalArgumentException("Number of messages l has to be greater 0, but it is: " + numberOfMessages);
        }

        // Y_i's in paper
        GroupElement[] group1ElementsYi = IntStream.range(0, numberOfMessages).mapToObj(a -> plaintextGroupElement.getStructure().getUniformlyRandomElement())
                .toArray(GroupElement[]::new);

        // Z_p element v in paper
        ZpElement exponentV = zp.getUniformlyRandomElement();

        // Set public key ( verification key)
        SPSGroth15VerificationKey pk = new SPSGroth15VerificationKey();
        pk.setGroupElementsYi(group1ElementsYi);
        pk.setGroupElementV(pp.getOtherGroupGenerator().pow(exponentV));

        // Set secret key (signing key)
        SPSGroth15SigningKey sk = new SPSGroth15SigningKey();
        sk.setExponentV(exponentV);
        sk.setPk(pk);

        return new SignatureKeyPair<>(pk, sk);
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {
        if (plainText instanceof GroupElementPlainText) {
            plainText = new MessageBlock(plainText);
        }
        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        if (!(secretKey instanceof SPSGroth15SigningKey)) {
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }
        // sign messages of type MessageBlock
        MessageBlock messageBlock = (MessageBlock) plainText;

        SPSGroth15SigningKey sk = (SPSGroth15SigningKey) secretKey;

        if (messageBlock.length() != sk.getNumberOfMessages()) {
            throw new IllegalArgumentException("Not a valid block size for this scheme. Has to be "
                    + sk.getNumberOfMessages() + ", but it is" + messageBlock.length());
        }
        if (!(messageBlock.length() > 0)) {
            throw new IllegalArgumentException("Number of messages l has to be greater 0, but it is: " + messageBlock.length());
        }


        // random exponent for signature out of Z_p^*
        ZpElement exponentR = pp.getZp().getUniformlyRandomUnit();

        // first element of signature, \hat(R) in paper
        GroupElement otherGroupElementR = pp.getOtherGroupGenerator().pow(exponentR);

        GroupElement plaintextGroupElementS = sk.getPk().getGroupElementsYi()[0].op(pp.getPlaintextGroupGenerator().pow(sk.getExponentV())).pow(exponentR.inv());

        // {T_i}'s in paper
        GroupElement[] plaintextGroupElementsTi = IntStream.range(0, messageBlock.length()).mapToObj(a -> sk.getPk().getGroupElementsYi()[a].pow(sk.getExponentV()).op(((GroupElementPlainText) messageBlock.get(a)).get()).pow(exponentR.inv()).compute())
                .toArray(GroupElement[]::new);

/*        for (int i = 0; i < sk.getNumberOfMessages(); i++) {
            if (!(messageBlock.get(i) instanceof GroupElementPlainText)
                    || messageBlock.get(i) == null
                    || !((GroupElementPlainText) messageBlock.get(i)).get().getStructure()
                    .equals(pp.getBilinearMap().getG1())) {
                throw new IllegalArgumentException("Not a valid plaintext for this scheme");
            }
            group1ElementHatR = group1ElementHatR.op(
                    ((GroupElementPlainText) messageBlock.get(i)).get().pow(sk.getExponentV()[i])
            );
        }*/



        GroupElement sigmaHatR = otherGroupElementR.compute();
        GroupElement sigmaS = plaintextGroupElementS.compute();
        GroupElement[] sigmaTi = plaintextGroupElementsTi;

        return new SPSGroth15Signature(sigmaHatR, sigmaS, sigmaTi);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {
        if (plainText instanceof GroupElementPlainText) {
            plainText = new MessageBlock(plainText);
        }
        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        if (!(signature instanceof SPSGroth15Signature)) {
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }
        if (!(publicKey instanceof SPSGroth15VerificationKey)) {
            throw new IllegalArgumentException("Not a valid public key for this scheme");
        }


        MessageBlock messageBlock = (MessageBlock) plainText;
        SPSGroth15VerificationKey pk = (SPSGroth15VerificationKey) publicKey;
        SPSGroth15Signature sigma = (SPSGroth15Signature) signature;



        // Check if verification equation of multi message signature scheme holds
        GroupElement firstPPE = applyMap(sigma.getGroupElementSigma2S(), sigma.getGroupElementSigma1HatR());
        GroupElement firstPPERHS = applyMap(pk.getGroupElementsYi()[0], pp.getOtherGroupGenerator()).op(applyMap(pp.getPlaintextGroupGenerator(), pk.groupElementV));
        firstPPE.compute();
        firstPPERHS.compute();

        GroupElement secondPPE = pp.getBilinearMap().getGT().getNeutralElement();

        for (int i = 0; i < pk.getNumberOfMessages(); i++) {
            secondPPE = secondPPE.op(
                    applyMap(sigma.getGroupElementSigma3Ti()[i], sigma.getGroupElementSigma1HatR()).inv()
                            .op(
                                    applyMap(pk.getGroupElementsYi()[i],pk.getGroupElementV())
                                            .op(
                                                    applyMap(
                                                            ((GroupElementPlainText) messageBlock.get(i)).get(),
                                                            pp.getOtherGroupGenerator()
                                                    )
                                            )

                            )
            );
        }
        secondPPE.compute();


        GroupElement neutral = pp.getBilinearMap().getGT().getNeutralElement();

        return firstPPE.equals(firstPPERHS) && secondPPE.equals(neutral);
    }

    /**
     * Applies the bilinear map according to the type of the Groth15 SPS.
     * @param plaintextGroupElement group element from the group where the plaintext/message is from
     * @param otherGroupElement group element form the group where the plaintext/message is not from
     */
    public GroupElement applyMap(GroupElement plaintextGroupElement, GroupElement otherGroupElement){
        if(pp.type == SPSGroth15PublicParametersGen.Groth15Type.type1){
            return pp.getBilinearMap().apply(plaintextGroupElement, otherGroupElement);
        }else{
            return pp.getBilinearMap().apply(otherGroupElement, plaintextGroupElement);
        }
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public MessageBlock restorePlainText(Representation repr) {
        return new MessageBlock(repr, r -> new GroupElementPlainText(r, pp.getPlaintextGroupGenerator().getStructure()));
    }

    @Override
    public SPSGroth15Signature restoreSignature(Representation repr) {
        return new SPSGroth15Signature(repr, this.pp.getPlaintextGroupGenerator().getStructure(), this.pp.getOtherGroupGenerator().getStructure());
    }

    @Override
    public SPSGroth15SigningKey restoreSigningKey(Representation repr) {
        return new SPSGroth15SigningKey(repr, this.pp.getZp(), this);
    }

    @Override
    public SPSGroth15VerificationKey restoreVerificationKey(Representation repr) {
        return new SPSGroth15VerificationKey(this.pp.getPlaintextGroupGenerator().getStructure(), this.pp.getOtherGroupGenerator().getStructure(), repr);
    }

    public SPSGroth15PublicParameters getPp() {
        return pp;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pp == null) ? 0 : pp.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other)
            return true;
        if (other == null || getClass() != other.getClass())
            return false;
        SPSGroth15SignatureScheme that = (SPSGroth15SignatureScheme) other;
        return Objects.equals(pp, that.pp);
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return mapToPlaintext(bytes, ((SPSGroth15VerificationKey) pk).getNumberOfMessages());
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, SigningKey sk) {
        return mapToPlaintext(bytes, ((SPSGroth15SigningKey) sk).getNumberOfMessages());
    }

    private MessageBlock mapToPlaintext(byte[] bytes, int messageBlockLength) {
        // returns (P^m, P, ..., P) where m = Z_p.injectiveValueOf(bytes).
        // this makes sure different messages produce different equivalence classes

        GroupElementPlainText[] msgBlock = new GroupElementPlainText[messageBlockLength];
        msgBlock[0] = new GroupElementPlainText(
                pp.getPlaintextGroupGenerator().pow(pp.getZp().injectiveValueOf(bytes))
        );
        for (int i = 1; i < msgBlock.length; i++) {
            msgBlock[i] = new GroupElementPlainText(pp.getPlaintextGroupGenerator());
        }

        return new MessageBlock(msgBlock);
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getBilinearMap().getG1().size().bitLength() - 1) / 8;
    }

}
