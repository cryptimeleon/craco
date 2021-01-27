package de.upb.crypto.craco.sig.bbs;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.*;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.rings.zn.Zn;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * Signature scheme that was originally presentet in [1] by Boneh, Boyen and Shacham. The version implemented is the
 * one presented in [2] which is the extension mentioned in the original paper. The result is a block signature scheme.
 * <p>
 * Bilinear map type: 2
 * <p>
 * [1] Dan Boneh, Xavier Boyen, and Hovav Shacham, "Short group signatures", in Advances in Cryptology CRYPTO 2004,
 * 2004
 * <p>
 * [2] F. Eidens, Anonymous Credential System based on the q-Strong Diffie-Hellman Assumption 2015.
 *
 *
 */
public class BBSBSignatureScheme implements StandardMultiMessageSignatureScheme {

    private BBSBPublicParameter pp;

    public BBSBSignatureScheme(Representation repr) {
        pp = new BBSBPublicParameter(repr);
    }

    public BBSBSignatureScheme(BBSBPublicParameter pp) {
        super();
        this.pp = pp;
    }

    @Override
    public Representation getRepresentation() {
        return pp.getRepresentation();
    }

    @Override
    public SignatureKeyPair<BBSBVerificationKey, BBSBSigningKey> generateKeyPair(int numberOfMessages) {
        // Set other variables (cf. KeyGen() algorithm)
        Zp zp = pp.getZp();
        GroupElement g2 = pp.getG2();
        ZpElement exponentGamma = zp.getUniformlyRandomUnit(); // secret for sk
        GroupElement w = g2.pow(exponentGamma).compute(); // g_2^{\gamma} for pk

        ZpElement[] ziExponents = new ZpElement[numberOfMessages + 1];

        ziExponents = Arrays.stream(ziExponents).map(a -> zp.getUniformlyRandomElement()).toArray(ZpElement[]::new);

        GroupElement[] uiG2Elements = Arrays.stream(ziExponents).map(zi -> g2.pow(zi).compute()).toArray(GroupElement[]::new);

        // Set skO and pkO with results
        BBSBSigningKey sk = new BBSBSigningKey();
        sk.setExponentGamma(exponentGamma);
        sk.setZiExponents(ziExponents);

        BBSBVerificationKey pk = new BBSBVerificationKey();
        pk.setUiG2Elements(uiG2Elements);
        pk.setW(w);

        return new SignatureKeyPair<>(pk, sk);
    }

    @Override
    public BBSABSignature sign(PlainText plainText, SigningKey secretKey) {
        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        if (!(secretKey instanceof BBSBSigningKey)) {
            throw new IllegalArgumentException("Not a valid signing key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        BBSBSigningKey sk = (BBSBSigningKey) secretKey;

        if (messageBlock.length() != sk.getNumberOfMessages()) {
            throw new IllegalArgumentException("Not a valid block size for this scheme");
        }

        ZpElement exponentX; // x in the paper
        do {
            exponentX = pp.getZp().getUniformlyRandomElement();
        } while (exponentX.equals(sk.getExponentGamma().neg()));

        ZpElement exponentSPrime = pp.getZp().getUniformlyRandomElement(); // s in the signature

        ZpElement resultExponent = pp.getZp().getOneElement();

        resultExponent = resultExponent.add(sk.getZiExponents()[0].mul(exponentSPrime)); // 1+s*z_0, where g_1^{z_0}=h_0

        // now compute 1+s*z_0+Sum( zi*mi )
        for (int i = 1; i <= sk.getNumberOfMessages(); i++) {
            resultExponent = resultExponent
                    .add(sk.getZiExponents()[i]
                            .mul((ZpElement) ((RingElementPlainText) messageBlock.get(i - 1)).getRingElement()));
        }

        // pre-compute the group element h_0^{s^\prime} \cdot h_1^{m_1} \cdot
        // \ldots \cdot h_L^{m_L}
        GroupElement c = pp.getG1();

        c = c.pow(resultExponent);

        Zn.ZnElement exponent = exponentX.add(sk.getExponentGamma()).inv();// 1/(x+gamma)

        GroupElement signatureElementA = c.pow(exponent).compute(); // A in the paper

        return new BBSABSignature(signatureElementA, exponentX, exponentSPrime);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {
        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        }
        if (!(signature instanceof BBSABSignature)) {
            throw new IllegalArgumentException("Not a valid signature for this scheme");
        }
        if (!(publicKey instanceof BBSBVerificationKey)) {
            throw new IllegalArgumentException("Not a valid public key for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        BBSBVerificationKey pk = (BBSBVerificationKey) publicKey;
        BBSABSignature sigma = (BBSABSignature) signature;

        GroupElement rebuildC = pp.getG1();

        rebuildC = rebuildC.op(pp.getGroupHom().apply(pk.getUiG2Elements()[0]).pow(sigma.getExponentS())); // h_0^s

        // now compute 1+s*z_0+Sum( zi*mi )
        for (int i = 1; i <= pk.getNumberOfMessages(); i++) {
            rebuildC = rebuildC.op(pk.getUiG2Elements()[i]
                    .pow((ZpElement) ((RingElementPlainText) messageBlock.get(i - 1)).getRingElement()));
        }

        GroupElement g2 = pp.getG2();
        GroupElement rightHandSide = pp.getBilinearMap().apply(rebuildC, g2);
        GroupElement leftHandSide = pp.getBilinearMap().apply(sigma.getElementA(),
                pk.getW().op(g2.pow(sigma.getExponentX())));
        return leftHandSide.equals(rightHandSide);
    }

    @Override
    public MessageBlock getPlainText(Representation repr) {
        return new MessageBlock(repr, RingElementPlainText::new);
    }

    @Override
    public BBSABSignature getSignature(Representation repr) {
        return new BBSABSignature(repr, pp.getGroupG1());
    }

    @Override
    public BBSBSigningKey getSigningKey(Representation repr) {
        return new BBSBSigningKey(repr, pp.getZp());
    }

    @Override
    public BBSBVerificationKey getVerificationKey(Representation repr) {
        return new BBSBVerificationKey(repr, pp.getGroupG2());
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
        BBSBSignatureScheme other = (BBSBSignatureScheme) obj;
        return Objects.equals(pp, other.pp);
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return mapToPlaintext(bytes, ((BBSBVerificationKey) pk).getNumberOfMessages());
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        return mapToPlaintext(bytes, ((BBSBSigningKey) sk).getNumberOfMessages());
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getGroupG1().size().bitLength() - 1) / 8;
    }

    protected MessageBlock mapToPlaintext(byte[] bytes, int messageBlockLength) {
        //Result will be a vector (zp.injectiveValueOf(bytes), 0, ..., 0)
        Zp zp = pp.getZp();
        RingElementPlainText zero = new RingElementPlainText(zp.getZeroElement());

        RingElementPlainText[] msgBlock = new RingElementPlainText[messageBlockLength];
        msgBlock[0] = new RingElementPlainText(zp.injectiveValueOf(bytes));
        for (int i = 1; i < msgBlock.length; i++) {
            msgBlock[i] = zero;
        }

        return new MessageBlock(msgBlock);
    }

    public BBSBPublicParameter getPublicParameters() {
        return pp;
    }
}
