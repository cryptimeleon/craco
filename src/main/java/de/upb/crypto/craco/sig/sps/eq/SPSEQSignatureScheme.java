package de.upb.crypto.craco.sig.sps.eq;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.signature.*;
import de.upb.crypto.math.interfaces.mappings.PairingProductExpression;
import de.upb.crypto.math.interfaces.structures.FutureGroupElement;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.interfaces.structures.PowProductExpression;
import de.upb.crypto.math.pairings.bn.BarretoNaehrigBilinearGroup;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zn;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * Signature scheme that was originally presented in [1] by Fuchsbauer, Hanser, and Slamanig. The result is
 * structure-preserving signatures on equivalence classes.
 * <p>
 * Bilinear map type: 3
 * <p>
 * [1] Georg Fuchsbauer and Christian Hanser and Daniel Slamanig, "Structure-Preserving Signatures on Equivalence Classes and Constant-Size Anonymous Credentials", in Cryptology ePrint Archive, Report
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
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
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
        ZpElement exponentsXi[] = IntStream.range(0, numberOfMessages).mapToObj(a -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        // \hat{X_i}'s in paper
        GroupElement[] group2ElementsHatXi =
                Arrays.stream(exponentsXi).map(group2ElementTildeG::pow).toArray(GroupElement[]::new);

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
            throw new IllegalArgumentException("Not a valid block size for this scheme. Has to be " + sk.getNumberOfMessages() + ", but it is" + messageBlock.size());
        }
        if (!(messageBlock.size() > 1)) {
            throw new IllegalArgumentException("Number of messages l has to be greater 1, but it is: " + messageBlock.size());
        }


        // first element of signature, Z in paper
        PowProductExpression group1ElementZ = pp.getBilinearMap().getG1().powProductExpression();
        // random exponent for signature out of Z_p^*
        ZpElement y = pp.getZp().getUniformlyRandomUnit();

        for (int i = 0; i < sk.getNumberOfMessages(); i++) {
            if (!(messageBlock.get(i) instanceof GroupElementPlainText)
                    || messageBlock.get(i) == null
                    || !((GroupElementPlainText) messageBlock.get(i)).get().getStructure()
                    .equals(pp.getBilinearMap().getG1())) {
                throw new IllegalArgumentException("Not a valid plain text for this scheme");
            }
            group1ElementZ.op(((GroupElementPlainText) messageBlock.get(i)).get(), sk.getExponentsXi()[i]);
        }
        group1ElementZ.pow(y);

        // second element of signature, Y in paper
        var group1ElementSigma2 = pp.getGroup1ElementP().asPowProductExpression().pow(y.inv());

        // third element of signature, \hat{Y} in paper
        var group2ElementSigma3 = pp.getGroup2ElementHatP().asPowProductExpression().pow(y.inv());
        var sigmaZ = group1ElementZ.evaluateConcurrent();
        var sigmaY = group1ElementSigma2.evaluateConcurrent();
        var sigmaHatY = group2ElementSigma3.evaluateConcurrent();

        return new SPSEQSignature(sigmaZ.get(), sigmaY.get(), sigmaHatY.get());
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

        PairingProductExpression firstPPE = pp.getBilinearMap().pairingProductExpression(), secondPPE = pp.getBilinearMap().pairingProductExpression();

        // Check if verification equation of multi message signature scheme holds
        // First pairing product equation: e(Z,\hat{Y})^{-1} * \prod_{i \in [l]} e(M_i,\hat{X}_i) = 1_{G_T}
        firstPPE.op(sigma.getGroup1ElementSigma1Z(), sigma.getGroup1ElementSigma3HatY()).inv();
        for (int i = 0; i < pk.getNumberOfMessages(); i++) {
            firstPPE.op(((GroupElementPlainText) messageBlock.get(i)).get(), pk.getGroup2ElementsHatXi()[i]);
        }

        if (!firstPPE.evaluateConcurrent().equals(pp.getBilinearMap().getGT().getNeutralElement())) {
            return false;
        }

        // Second pairing product equation: e(P,\hat{Y})^{-1} * e(Y,\hat{P}) = 1_{G_T}
        secondPPE.op(pp.getGroup1ElementP(), sigma.getGroup1ElementSigma3HatY()).inv();
        secondPPE.op(sigma.getGroup1ElementSigma2Y(), pp.getGroup2ElementHatP());

        if (!secondPPE.evaluateConcurrent().equals(pp.getBilinearMap().getGT().getNeutralElement())) {
            return false;
        }

        // verification equation does hold true
        return true;
    }

    /**
     * The change representative method returns a signature matching the new representative of [M]_R.
     * The new representative of [M]_R is supposed to be generated externally by using the plain text (M) and
     * element mu. The matching signature sigma' for the new representative mu*M of [M]_R is computed such that
     * Verify(mu*M,sigma') = 1.
     * See paper [1] for details.
     *
     * @param plainText
     * @param signature
     * @param mu
     * @param publicKey
     * @return null of the signature given is not valid on plainText under publicKey, else it returns a valid signature
     *         on mu*plainText
     */
    @Override
    public Signature chgRep(PlainText plainText, Signature signature, Zn.ZnElement mu, VerificationKey publicKey) {
        // First verify the original signature on the plaintext M, if it is not valid return null
        if (!verify(plainText, signature, publicKey)) {
            return null;
        }
        // Method verify also checks the plaintext, signature, and public key through instanceof checks.
        // We only have to check the element mu
        if (!(mu instanceof ZpElement)) {
            throw new IllegalArgumentException("Not a valid element 'mu' for this scheme");
        }

        // Zp element to randomize the signature
        ZpElement psi = pp.getZp().getUniformlyRandomUnit();
        ZpElement psiInv = psi.inv();

        SPSEQSignature sigma = (SPSEQSignature) signature;
        var sigmaZ = sigma.getGroup1ElementSigma1Z().asPowProductExpression().pow(psi.mul(mu)).evaluateConcurrent();
        var sigmaY = sigma.getGroup1ElementSigma2Y().asPowProductExpression().pow(psiInv).evaluateConcurrent();
        var sigmaHatY = sigma.getGroup1ElementSigma3HatY().asPowProductExpression().pow(psiInv).evaluateConcurrent();

        return new SPSEQSignature(sigmaZ.get(), sigmaY.get(), sigmaHatY.get());
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
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
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SPSEQSignatureScheme other = (SPSEQSignatureScheme) obj;
        if (pp == null) {
            if (other.pp != null)
                return false;
        } else if (!pp.equals(other.pp))
            return false;
        return true;
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, VerificationKey pk) {
        throw new IllegalArgumentException();
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, SigningKey sk) {
        throw new IllegalArgumentException();
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        throw new IllegalArgumentException();
    }

}
