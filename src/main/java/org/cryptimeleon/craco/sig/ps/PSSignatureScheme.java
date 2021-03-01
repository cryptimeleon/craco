package org.cryptimeleon.craco.sig.ps;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Signature scheme that was originally presented in chapter 4.2 of [1] by Pointcheval and Sanders. The result is a
 * block signature scheme.
 * <p>
 * Bilinear map type: 3
 * <p>
 * [1] David Pointcheval and Olivier Sanders, "Short Randomizable Signatures", in Cryptology ePrint Archive, Report
 * 2015/525, 2015.
 *
 *
 */

public class PSSignatureScheme implements StandardMultiMessageSignatureScheme {

    /**
     * Public parameters of the signature scheme.
     */
    @Represented
    protected PSPublicParameters pp;

    public PSSignatureScheme(PSPublicParameters pp) {
        super();
        this.pp = pp;
    }

    public PSSignatureScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public SignatureKeyPair<? extends PSVerificationKey, ? extends PSSigningKey> generateKeyPair(int numberOfMessages) {
        // Do actual key generation (cf. Setup() and KeyGen() algorithm)
        BigInteger size = pp.getBilinearMap().getG1().size();
        Group group2 = pp.getBilinearMap().getG2();
        Zp zp = new Zp(size);
        GroupElement group2ElementTildeG = group2.getUniformlyRandomNonNeutral().compute();

        // x in paper
        ZpElement exponentX = zp.getUniformlyRandomElement();
        // y_i's in paper
        RingElementVector exponentsYi = zp.getUniformlyRandomElements(numberOfMessages);

        // \tilde{X} in paper
        GroupElement group2ElementX = group2ElementTildeG.pow(exponentX).compute();
        // \tilde{Y_i}'s in paper
        GroupElementVector group2ElementsYi = group2ElementTildeG.pow(exponentsYi);

        // Set secret key (signing key)
        PSSigningKey sk = new PSSigningKey(exponentX, exponentsYi);

        // Set public key ( verification key)
        PSVerificationKey pk = new PSVerificationKey(group2ElementTildeG, group2ElementX, group2ElementsYi);
        return new SignatureKeyPair<>(pk, sk);
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {
        if (plainText instanceof RingElementPlainText) {
            plainText = new MessageBlock(plainText);
        }

        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        if (!(secretKey instanceof PSSigningKey)) {
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        PSSigningKey sk = (PSSigningKey) secretKey;

        if (messageBlock.length() != sk.getNumberOfMessages()) {
            throw new IllegalArgumentException("Not a valid block size for this scheme");
        }

        // first element of signature, sigma_1 in paper
        GroupElement group1ElementH = pp.getBilinearMap().getG1().getUniformlyRandomNonNeutral().compute();

        // compute resultExponent = x + y_i * m_i
        ZpElement resultExponent = sk.getExponentX().add(
                ((MessageBlock) plainText).map(pt -> ((RingElementPlainText) pt).getRingElement(), RingElementVector::new)
                .innerProduct(sk.getExponentsYi())
        );

        // second element of signature, sigma_2 in paper
        GroupElement group1ElementSigma2 = group1ElementH.pow(resultExponent.getInteger()).compute();

        return new PSSignature(group1ElementH, group1ElementSigma2);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {
        if (plainText instanceof RingElementPlainText) {
            plainText = new MessageBlock(plainText);
        }

        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        if (!(signature instanceof PSSignature)) {
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }
        if (!(publicKey instanceof PSVerificationKey)) {
            throw new IllegalArgumentException("Not a valid public key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        PSVerificationKey pk = (PSVerificationKey) publicKey;
        PSSignature sigma = (PSSignature) signature;

        // invalid signature if sigma_1 == 1_{G_1}
        if (sigma.getGroup1ElementSigma1().isNeutralElement())
            return false;

        // Check if verification equation of multi message signature scheme holds
        GroupElement leftHandSide, rightHandSide;

        // Compute right hand side of verification equation
        rightHandSide = pp.getBilinearMap().apply(sigma.getGroup1ElementSigma2(), pk.getGroup2ElementTildeG());

        // Compute left hand side of verification equation
        GroupElement group2Elem = pk.getGroup2ElementTildeX().op(
                pk.getGroup2ElementsTildeYi().innerProduct(messageBlock.map(pt -> ((RingElementPlainText) pt).getRingElement(), RingElementVector::new))
        ); // group2Elem = \tilde(X) * prod \tilde(Y)_j^{m_j}

        leftHandSide = pp.getBilinearMap().apply(sigma.getGroup1ElementSigma1(), group2Elem);

        return leftHandSide.equals(rightHandSide);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public MessageBlock restorePlainText(Representation repr) {
        return new MessageBlock(repr, RingElementPlainText::new);
    }

    @Override
    public PSSignature restoreSignature(Representation repr) {
        return new PSSignature(repr, this.pp.getBilinearMap().getG1());
    }

    @Override
    public PSSigningKey restoreSigningKey(Representation repr) {
        return new PSSigningKey(repr, this.pp.getZp());
    }

    @Override
    public PSVerificationKey restoreVerificationKey(Representation repr) {
        return new PSVerificationKey(this.pp.getBilinearMap().getG2(), repr);
    }

    public PSPublicParameters getPp() {
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
        PSSignatureScheme other = (PSSignatureScheme) obj;
        return Objects.equals(pp, other.pp);
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return mapToPlaintext(bytes, ((PSVerificationKey) pk).getNumberOfMessages());
    }

    @Override
    public MessageBlock mapToPlaintext(byte[] bytes, SigningKey sk) {
        return mapToPlaintext(bytes, ((PSSigningKey) sk).getNumberOfMessages());
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getBilinearMap().getG1().size().bitLength() - 1) / 8;
    }

    protected MessageBlock mapToPlaintext(byte[] bytes, int messageBlockLength) {
        //Result will be a vector (zp.injectiveValueOf(bytes), 0, ..., 0)
        return new RingElementVector(pp.getZp().injectiveValueOf(bytes)).pad(pp.getZp().getZeroElement(), messageBlockLength)
                .map(RingElementPlainText::new, MessageBlock::new);
    }
}
