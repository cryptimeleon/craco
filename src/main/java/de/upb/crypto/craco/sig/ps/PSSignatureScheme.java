package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.common.plaintexts.MessageBlock;
import de.upb.crypto.craco.common.plaintexts.PlainText;
import de.upb.crypto.craco.common.plaintexts.RingElementPlainText;
import de.upb.crypto.craco.sig.*;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

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

    protected PSSignatureScheme() {
        super();
    }

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
        ZpElement[] exponentsYi = IntStream.range(0, numberOfMessages).mapToObj(a -> zp.getUniformlyRandomElement())
                .toArray(ZpElement[]::new);

        // \tilde{X} in paper
        GroupElement group2ElementX = group2ElementTildeG.pow(exponentX).compute();
        // \tilde{Y_i}'s in paper
        GroupElement[] group2ElementsYi =
                Arrays.stream(exponentsYi).map(y -> group2ElementTildeG.pow(y).compute()).toArray(GroupElement[]::new);

        // Set secret key (signing key)
        PSSigningKey sk = new PSSigningKey();
        sk.setExponentX(exponentX);
        sk.setExponentsYi(exponentsYi);

        // Set public key ( verification key)
        PSVerificationKey pk = new PSVerificationKey();
        pk.setGroup2ElementTildeG(group2ElementTildeG);
        pk.setGroup2ElementTildeX(group2ElementX);
        pk.setGroup2ElementsTildeYi(group2ElementsYi);

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
        ZpElement resultExponent = pp.getZp().getZeroElement();

        //2.8; mirkoj: fixed the use of resultExponent.add
        resultExponent = resultExponent.add(sk.getExponentX());

        for (int i = 0; i < sk.getNumberOfMessages(); i++) {
            if (!(messageBlock.get(i) instanceof RingElementPlainText)
                    || messageBlock.get(i) == null
                    || !((RingElementPlainText) messageBlock.get(i)).getRingElement().getStructure()
                    .equals(pp.getZp())) {
                throw new IllegalArgumentException("Not a valid plain text for this scheme");
            }
            resultExponent = resultExponent.add(sk.getExponentsYi()[i]
                    .mul((ZpElement) ((RingElementPlainText) messageBlock.get(i)).getRingElement()));
        }

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
        GroupElement group2Elem =
                pp.getBilinearMap().getG2().getNeutralElement(); // group2Elem = \tilde(X) * prod \tilde(Y)_j^{m_j}
        //2.8 mirkoj: fixed the use of GroupElment.op
        group2Elem = group2Elem.op(pk.getGroup2ElementTildeX());

        for (int i = 0; i < pk.getNumberOfMessages(); i++) {
            group2Elem = group2Elem.op(pk.getGroup2ElementsTildeYi()[i]
                    .pow((ZpElement) ((RingElementPlainText) messageBlock.get(i)).getRingElement()));
        }

        leftHandSide = pp.getBilinearMap().apply(sigma.getGroup1ElementSigma1(), group2Elem);

        return leftHandSide.equals(rightHandSide);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public MessageBlock getPlainText(Representation repr) {
        return new MessageBlock(repr, RingElementPlainText::new);
    }

    @Override
    public PSSignature getSignature(Representation repr) {
        return new PSSignature(repr, this.pp.getBilinearMap().getG1());
    }

    @Override
    public PSSigningKey getSigningKey(Representation repr) {
        return new PSSigningKey(repr, this.pp.getZp());
    }

    @Override
    public PSVerificationKey getVerificationKey(Representation repr) {
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
        Zp zp = pp.getZp();
        RingElementPlainText zero = new RingElementPlainText(zp.getZeroElement());

        RingElementPlainText[] msgBlock = new RingElementPlainText[messageBlockLength];
        msgBlock[0] = new RingElementPlainText(zp.injectiveValueOf(bytes));
        for (int i = 1; i < msgBlock.length; i++) {
            msgBlock[i] = zero;
        }

        return new MessageBlock(msgBlock);
    }
}
