package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.sig.interfaces.*;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.rings.zn.Zn;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Signature scheme that was originally presented in [1] by Fuchsbauer, Hanser, and Slamanig. The result is
 * structure-preserving signatures on equivalence classes. This is the version for messages from G_1.
 * A version for messages in G_2 can be obtained by swapping membership of all elements.
 * <p>
 * Bilinear map type: 3
 * <p>
 * [1] Georg Fuchsbauer and Christian Hanser and Daniel Slamanig, "Structure-Preserving Signatures on Equivalence Classes
 * and Constant-Size Anonymous Credentials", in Cryptology ePrint Archive, Report
 * 2014/944, 2014.
 *
 * @author Fabian Eidens
 */

public class SPSEQSignatureScheme implements StructurePreservingSignatureEQScheme {

    /**
     * Public parameters of the signature scheme.
     */
    @Represented
    protected SPSEQPublicParameters pp;

    protected SPSEQSignatureScheme() {
        super();
    }

    public SPSEQSignatureScheme(SPSEQPublicParameters pp) {
        super();
        this.pp = pp;
    }

    public SPSEQSignatureScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public SignatureKeyPair<? extends SPSEQVerificationKey, ? extends SPSEQSigningKey> generateKeyPair(int numberOfMessages) {
        // Do actual key generation (cf. KeyGen algorithm)
        Zp zp = pp.getZp();
        GroupElement group2ElementTildeG = pp.getGroup2ElementHatP();

        // check if number of messages l > 1, only for l > 1 EUF-CMA holds.
        if (!(numberOfMessages > 1)) {
            throw new IllegalArgumentException("Number of messages l has to be greater 1, but it is: " + numberOfMessages);
        }

        // x_i's in paper
        ZpElement[] exponentsXi = IntStream.range(0, numberOfMessages).mapToObj(a -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        // \hat{X_i}'s in paper
        GroupElement[] group2ElementsHatXi =
                Arrays.stream(exponentsXi).map(x -> group2ElementTildeG.pow(x).compute()).toArray(GroupElement[]::new);

        // Set secret key (signing key)
        SPSEQSigningKey sk = new SPSEQSigningKey();
        sk.setExponentsXi(exponentsXi);

        // Set public key ( verification key)
        SPSEQVerificationKey pk = new SPSEQVerificationKey();
        pk.setGroup2ElementsHatXi(group2ElementsHatXi);

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
        if (!(secretKey instanceof SPSEQSigningKey)) {
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }
        // we sign messages of type MessageBlock
        MessageBlock messageBlock = (MessageBlock) plainText;

        SPSEQSigningKey sk = (SPSEQSigningKey) secretKey;

        if (messageBlock.size() != sk.getNumberOfMessages()) {
            throw new IllegalArgumentException("Not a valid block size for this scheme. Has to be "
                    + sk.getNumberOfMessages() + ", but it is" + messageBlock.size());
        }
        if (!(messageBlock.size() > 1)) {
            throw new IllegalArgumentException("Number of messages l has to be greater 1, but it is: " + messageBlock.size());
        }


        // first element of signature, Z in paper
        GroupElement group1ElementZ = pp.getBilinearMap().getG1().getNeutralElement();
        // random exponent for signature out of Z_p^*
        ZpElement y = pp.getZp().getUniformlyRandomUnit();

        for (int i = 0; i < sk.getNumberOfMessages(); i++) {
            if (!(messageBlock.get(i) instanceof GroupElementPlainText)
                    || messageBlock.get(i) == null
                    || !((GroupElementPlainText) messageBlock.get(i)).get().getStructure()
                    .equals(pp.getBilinearMap().getG1())) {
                throw new IllegalArgumentException("Not a valid plain text for this scheme");
            }
            group1ElementZ = group1ElementZ.op(
                    ((GroupElementPlainText) messageBlock.get(i)).get().pow(sk.getExponentsXi()[i])
            );
        }
        group1ElementZ = group1ElementZ.pow(y);

        GroupElement sigmaZ = group1ElementZ.compute();
        GroupElement sigmaY = pp.getGroup1ElementP().pow(y.inv()).compute();
        GroupElement sigmaHatY = pp.getGroup2ElementHatP().pow(y.inv()).compute();

        return new SPSEQSignature(sigmaZ, sigmaY, sigmaHatY);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {
        if (plainText instanceof GroupElementPlainText) {
            plainText = new MessageBlock(plainText);
        }
        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        if (!(signature instanceof SPSEQSignature)) {
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }
        if (!(publicKey instanceof SPSEQVerificationKey)) {
            throw new IllegalArgumentException("Not a valid public key for this scheme");
        }


        MessageBlock messageBlock = (MessageBlock) plainText;
        SPSEQVerificationKey pk = (SPSEQVerificationKey) publicKey;
        SPSEQSignature sigma = (SPSEQSignature) signature;

        // invalid signature if sigma_2_Y == 1_{G_1} or if sigma_2_hat_Y == 1_{G_2}
        if (sigma.getGroup1ElementSigma2Y().isNeutralElement() || sigma.getGroup1ElementSigma3HatY().isNeutralElement())
            return false;

        // Check if verification equation of multi message signature scheme holds
        // First pairing product equation: e(Z,\hat{Y})^{-1} * \prod_{i \in [l]} e(M_i,\hat{X}_i) = 1_{G_T}
        GroupElement firstPPE = pp.getBilinearMap()
                .apply(sigma.getGroup1ElementSigma1Z(), sigma.getGroup1ElementSigma3HatY())
                .inv();
        for (int i = 0; i < pk.getNumberOfMessages(); i++) {
            firstPPE = firstPPE.op(
                    pp.getBilinearMap().apply(
                            ((GroupElementPlainText) messageBlock.get(i)).get(),
                            pk.getGroup2ElementsHatXi()[i]
                    )
            );
        }
        firstPPE.compute();

        // Second pairing product equation: e(P,\hat{Y})^{-1} * e(Y,\hat{P}) = 1_{G_T}
        GroupElement secondPPE = pp.getBilinearMap()
                .apply(pp.getGroup1ElementP(), sigma.getGroup1ElementSigma3HatY())
                .inv();
        secondPPE = secondPPE.op(
                pp.getBilinearMap().apply(
                        sigma.getGroup1ElementSigma2Y(),
                        pp.getGroup2ElementHatP()
                )
        );
        secondPPE.compute();

        GroupElement neutral = pp.getBilinearMap().getGT().getNeutralElement();

        return firstPPE.equals(neutral) && secondPPE.equals(neutral);
    }

    @Override
    public Signature chgRep(Signature signature, Zn.ZnElement mu, VerificationKey publicKey) {
        if (!(signature instanceof SPSEQSignature)) {
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }
        if (!(publicKey instanceof SPSEQVerificationKey)) {
            throw new IllegalArgumentException("Not a valid public key for this scheme");
        }
        // We have to check that the element mu is of the correct type
        if (!(mu instanceof ZpElement)) {
            throw new IllegalArgumentException("Not a valid element 'mu' for change representative for this scheme");
        }

        // Zp element to randomize the signature
        ZpElement psi = pp.getZp().getUniformlyRandomUnit();
        ZpElement psiInv = psi.inv();

        SPSEQSignature sigma = (SPSEQSignature) signature;
        GroupElement sigmaZ = sigma.getGroup1ElementSigma1Z().pow(psi.mul(mu)).compute();
        GroupElement sigmaY = sigma.getGroup1ElementSigma2Y().pow(psiInv).compute();
        GroupElement sigmaHatY = sigma.getGroup1ElementSigma3HatY().pow(psiInv).compute();

        return new SPSEQSignature(sigmaZ, sigmaY, sigmaHatY);
    }

    @Override
    public Signature chgRepWithVerify(PlainText plainText, Signature signature, Zn.ZnElement mu, VerificationKey publicKey) {
        // First verify the original signature on the plaintext M, if it is not valid return null
        if (!verify(plainText, signature, publicKey)) {
            return null;
        }
        return chgRep(signature, mu, publicKey);
    }

    @Override
    public PlainText chgRepMessage(PlainText plainText, Zn.ZnElement mu) {
        if (plainText instanceof GroupElementPlainText) {
            plainText = new MessageBlock(plainText);
        }
        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        // We have to check that the element mu is of the correct type
        if (!(mu instanceof ZpElement)) {
            throw new IllegalArgumentException("Not a valid element 'mu' for change representative for this scheme");
        }
        // apply pow(mu) to every message element: M_i^{mu}
        return new MessageBlock(
                ((MessageBlock) plainText)
                        .parallelStream()
                        .map(m -> ((GroupElementPlainText) m).get().pow(mu).compute())
                        .map(GroupElementPlainText::new)
                        .collect(Collectors.toList())
        );
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public MessageBlock getPlainText(Representation repr) {
        return new MessageBlock(repr, r -> new GroupElementPlainText(r, pp.getBilinearMap().getG1()));
    }

    @Override
    public SPSEQSignature getSignature(Representation repr) {
        return new SPSEQSignature(repr, this.pp.getBilinearMap().getG1(), this.pp.getBilinearMap().getG2());
    }

    @Override
    public SPSEQSigningKey getSigningKey(Representation repr) {
        return new SPSEQSigningKey(repr, this.pp.getZp());
    }

    @Override
    public SPSEQVerificationKey getVerificationKey(Representation repr) {
        return new SPSEQVerificationKey(this.pp.getBilinearMap().getG2(), repr);
    }

    public SPSEQPublicParameters getPp() {
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
        SPSEQSignatureScheme that = (SPSEQSignatureScheme) other;
        return Objects.equals(pp, that.pp);
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return mapToPlaintext(bytes, ((SPSEQVerificationKey) pk).getNumberOfMessages());
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, SigningKey sk) {
        return mapToPlaintext(bytes, ((SPSEQSigningKey) sk).getNumberOfMessages());
    }

    private MessageBlock mapToPlaintext(byte[] bytes, int messageBlockLength) {
        // returns (P^m, P, ..., P) where m = Z_p.injectiveValueOf(bytes).
        // this makes sure different messages produce different equivalence classes

        GroupElementPlainText[] msgBlock = new GroupElementPlainText[messageBlockLength];
        msgBlock[0] = new GroupElementPlainText(
                pp.getGroup1ElementP().pow(pp.getZp().injectiveValueOf(bytes))
        );
        for (int i = 1; i < msgBlock.length; i++) {
            msgBlock[i] = new GroupElementPlainText(pp.getGroup1ElementP());
        }

        return new MessageBlock(msgBlock);
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getBilinearMap().getG1().size().bitLength() - 1) / 8;
    }

}
