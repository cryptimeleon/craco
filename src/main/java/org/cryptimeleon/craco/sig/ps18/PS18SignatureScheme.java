package org.cryptimeleon.craco.sig.ps18;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.ps.PSPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;
import java.util.stream.IntStream;

public class PS18SignatureScheme implements SignatureScheme {

    @Represented
    PSPublicParameters pp;

    public PS18SignatureScheme(PSPublicParameters pp) {
        this.pp = pp;
    }

    public PS18SignatureScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public SignatureKeyPair<PS18VerificationKey, PS18SigningKey>
    generateKeyPair(int numberOfMessages) {
        // get exponent field and store group2 for shorter usage
        Group group2 = pp.getBilinearMap().getG2();
        Zp zp = pp.getZp();

        // Pick \tilde{g} from G_2^*
        GroupElement group2ElementTildeG = group2.getUniformlyRandomNonNeutral().compute();
        // Pick x from Z_p^*
        Zp.ZpElement exponentX = zp.getUniformlyRandomUnit();
        // Pick y_1, ..., y_{r+1} from Z_p^* (r is number of messages)
        RingElementVector exponentsYi = RingElementVector.fromStream(IntStream.range(0, numberOfMessages + 1)
                .mapToObj(a -> zp.getUniformlyRandomUnit()));

        // Compute \tilde{X} = \tilde{g}^x
        GroupElement group2ElementTildeX = group2ElementTildeG.pow(exponentX).compute();
        // Compute (\tilde{Y_1}, ..., \tilde{Y_{r+1}}) = (\tilde{g}^{y_1}, ..., \tilde{g}^{y_{r+1}})
        GroupElementVector group2ElementsTildeYi =
                new GroupElementVector(exponentsYi.map(x -> group2ElementTildeG.pow((Zp.ZpElement) x).compute()));


        // Precompute for bases in multi-exponentiation
        group2ElementTildeX.precomputePow();
        group2ElementsTildeYi.precomputePow();

        // Construct secret signing key
        PS18SigningKey sk = new PS18SigningKey(exponentX, exponentsYi);

        // Construct public verification key
        PS18VerificationKey pk = new PS18VerificationKey(
                group2ElementTildeG,
                group2ElementTildeX,
                group2ElementsTildeYi
        );

        return new SignatureKeyPair<>(pk, sk);
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {
        // A single message needs to be converted to message vector with one message
        if (plainText instanceof RingElementPlainText) {
            plainText = new MessageBlock(plainText);
        }

        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Plaintext is not a 'MessageBlock' instance.");
        }
        if (!(secretKey instanceof PS18SigningKey)) {
            throw new IllegalArgumentException("Signing key is not a 'PS18SigningKey' instance.");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        PS18SigningKey sk = (PS18SigningKey) secretKey;

        if (messageBlock.length() != sk.getNumberOfMessages()) {
            throw new IllegalArgumentException("Message length does not match length " +
                    "supported by signing key.");
        }

        Zp zp = pp.getZp();

        // h in G_1^*, second element of signature
        GroupElement group1ElementSigma1 = pp.getBilinearMap().getG1()
                .getUniformlyRandomNonNeutral();

        // m' in Z_p, first element of signature
        Zp.ZpElement exponentPrimeM = zp.getUniformlyRandomElement();

        // Compute third element of signature
        GroupElement group1ElementSigma2 = computeSigma2(
                messageBlock, sk, exponentPrimeM, group1ElementSigma1
        );

        return new PS18Signature(exponentPrimeM, group1ElementSigma1, group1ElementSigma2);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {
        // A single message needs to be converted to message vector with one message
        if (plainText instanceof RingElementPlainText) {
            plainText = new MessageBlock(plainText);
        }

        if (!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("Plaintext is not a 'MessageBlock' instance.");
        }
        if (!(signature instanceof PS18Signature)) {
            throw new IllegalArgumentException("Signature is not a 'PS18Signature' instance.");
        }
        if (!(publicKey instanceof PS18VerificationKey)) {
            throw new IllegalArgumentException("Public key is not a 'PS18VerificationKey' " +
                    "instance.");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        PS18VerificationKey pk = (PS18VerificationKey) publicKey;
        PS18Signature sigma = (PS18Signature) signature;

        // Check that groupElementSigma1 is not neutral element of G_1
        if (sigma.getGroup1ElementSigma1().isNeutralElement())
            return false;

        // Check that bilinear pairing equation holds
        GroupElement leftHandSide, rightHandSide;

        rightHandSide = pp.getBilinearMap().apply(
                sigma.getGroup1ElementSigma2(), pk.getGroup2ElementTildeG()
        );

        leftHandSide = computeLeftHandSide(
                messageBlock, pk, sigma.getExponentPrimeM(), sigma.getGroup1ElementSigma1()
        );

        return leftHandSide.equals(rightHandSide);
    }

    /**
     * Computes sigma_2 in paper. Since this computation is shared between the regular
     * [PS18] and the random oracle version – just with a different exponentPrimeM –
     * we outsource it to this method.
     *
     * @param messageBlock message to sign.
     * @param sk signing key.
     * @param exponentPrimeM m' in paper.
     * @param sigma1 \sigma_1 (also h) in paper.
     * @return \sigma_2 from paper.
     */
    protected GroupElement computeSigma2(MessageBlock messageBlock, PS18SigningKey sk,
                                         Zp.ZpElement exponentPrimeM, GroupElement sigma1) {
        // First we compute the exponent = x + \sum_{i=1}{r}{y_i * m_i} + y_{r+1} * m'
        Zp.ZpElement resultExponent = sk.getExponentX();
        for (int i = 0; i < sk.getNumberOfMessages(); ++i) {
            if (messageBlock.get(i) == null) {
                throw new IllegalArgumentException(
                        String.format("%d'th message element is null.", i)
                );
            }
            PlainText messagePartI = messageBlock.get(i);
            if (!(messagePartI instanceof RingElementPlainText)) {
                throw new IllegalArgumentException(
                        String.format("%d'th message element is not a 'RingElementPlainText' instance.", i)
                );
            }
            RingElementPlainText messageRingElement = (RingElementPlainText) messagePartI;
            if (!(messageRingElement.getRingElement().getStructure().equals(pp.getZp()))) {
                throw new IllegalArgumentException(
                        String.format("%d'th message element is not an element of Zp.", i)
                );
            }
            Zp.ZpElement messageElement = (Zp.ZpElement) messageRingElement.getRingElement();
            resultExponent = resultExponent.add(sk.getExponentsYi().get(i).mul(messageElement));
        }
        resultExponent = resultExponent.add(
                sk.getExponentsYi().get(sk.getNumberOfMessages()).mul(exponentPrimeM)
        );
        // Now we exponentiate h with the exponent and return that as sigma_2.
        return sigma1.pow(resultExponent.asInteger());
    }

    /**
     * Computes left hand side of verification equation. Since this computation is shared between the regular
     * [PS18] and the random oracle version – just with a different exponentPrimeM –
     * we outsource it to this method.
     *
     * @param messageBlock message to verify signature for.
     * @param pk public verification key
     * @param exponentPrimeM m' in paper. First element of signature (for 4.2) or computed from message
     *                       using random oracle (hash function) (for ROM from 4.3).
     * @param sigma1 \sigma_1 in paper. Either second or first element of signature (see above).
     * @return element of G_T which is the left hand side of the verification equation.
     */
    protected GroupElement computeLeftHandSide(MessageBlock messageBlock, PS18VerificationKey pk,
                                               Zp.ZpElement exponentPrimeM, GroupElement sigma1) {
        // Computation of group element from G_2 for left hand side requires sum
        // \tilde{X} * \prod_{i=1}{r}{\tilde{Y}_i^{m_i}} * \tilde{Y}_{r+1}^{m'}
        // l = \tilde{X}
        GroupElement leftGroup2Elem = pk.getGroup2ElementTildeX();
        for (int i = 0; i < pk.getNumberOfMessages(); ++i) {
            if (messageBlock.get(i) == null) {
                throw new IllegalArgumentException(
                        String.format("%d'th message element is null.", i)
                );
            }
            PlainText messagePartI = messageBlock.get(i);
            if (!(messagePartI instanceof RingElementPlainText)) {
                throw new IllegalArgumentException(
                        String.format("%d'th message element is not a 'RingElementPlainText' " +
                                "instance.", i)
                );
            }
            RingElementPlainText messageRingElement = (RingElementPlainText) messagePartI;
            if (!(messageRingElement.getRingElement().getStructure().equals(pp.getZp()))) {
                throw new IllegalArgumentException(
                        String.format("%d'th message element is not an element of Zp.", i)
                );
            }
            Zp.ZpElement messageElement = (Zp.ZpElement) messageRingElement.getRingElement();
            leftGroup2Elem = leftGroup2Elem.op(
                    pk.getGroup2ElementsTildeYi().get(i).pow(messageElement)
            );
        }
        leftGroup2Elem = leftGroup2Elem.op(
                pk.getGroup2ElementsTildeYi().get(pk.getNumberOfMessages()).pow(exponentPrimeM)
        );

        return pp.getBilinearMap().apply(sigma1, leftGroup2Elem);
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        return mapToPlaintext(bytes, ((PS18SigningKey) sk).getNumberOfMessages());
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return mapToPlaintext(bytes, ((PS18VerificationKey) pk).getNumberOfMessages());
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getZp().size().bitLength() - 1) / 8;
    }

    protected MessageBlock mapToPlaintext(byte[] bytes, int messageBlockLength) {
        //Result will be a vector (zp.injectiveValueOf(bytes), 0, ..., 0)
        return new RingElementVector(pp.getZp().injectiveValueOf(bytes)).pad(pp.getZp().getZeroElement(), messageBlockLength)
                .map(RingElementPlainText::new, MessageBlock::new);
    }

    @Override
    public PlainText restorePlainText(Representation repr) {
        return new MessageBlock(repr, RingElementPlainText::new);
    }

    @Override
    public Signature restoreSignature(Representation repr) {
        return new PS18Signature(repr, this.pp.getZp(), this.pp.getBilinearMap().getG1());
    }

    @Override
    public SigningKey restoreSigningKey(Representation repr) {
        return new PS18SigningKey(repr, this.pp.getZp());
    }

    @Override
    public VerificationKey restoreVerificationKey(Representation repr) {
        return new PS18VerificationKey(repr, this.pp.getBilinearMap().getG2());
    }

    public PSPublicParameters getPp() {
        return pp;
    }

    @Override
    public int hashCode() {
        return pp.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        PS18SignatureScheme other = (PS18SignatureScheme) obj;
        return Objects.equals(pp, other.pp);
    }
}
