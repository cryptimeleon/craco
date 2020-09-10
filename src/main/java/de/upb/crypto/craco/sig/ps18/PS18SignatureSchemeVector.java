package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.cartesian.GroupElementVector;
import de.upb.crypto.math.structures.cartesian.Vector;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;
import java.util.stream.IntStream;

public class PS18SignatureSchemeVector extends PS18SignatureScheme {
    public PS18SignatureSchemeVector(PSPublicParameters pp) {
        super(pp);
    }

    public PS18SignatureSchemeVector(Representation repr) {
        super(repr);
    }

    public SignatureKeyPair<? extends PS18VerificationKeyVector, ? extends PS18SigningKey>
    generateKeyPairVector(int numberOfMessages) {
        // get exponent field and store group2 for shorter usage
        Group group2 = pp.getBilinearMap().getG2();
        Zp zp = pp.getZp();

        // Pick \tilde{g} from G_2^*
        GroupElement group2ElementTildeG = group2.getUniformlyRandomNonNeutral();
        // Pick x from Z_p^*
        Zp.ZpElement exponentX = zp.getUniformlyRandomUnit();
        // Pick y_1, ..., y_{r+1} from Z_p^* (r is number of messages)
        Zp.ZpElement[] exponentsYi = IntStream.range(0, numberOfMessages + 1)
                .mapToObj(a -> zp.getUniformlyRandomUnit())
                .toArray(Zp.ZpElement[]::new);

        // Compute \tilde{X} = \tilde{g}^x
        GroupElement group2ElementTildeX = group2ElementTildeG.pow(exponentX);
        // Compute (\tilde{Y_1}, ..., \tilde{Y_{r+1}}) = (\tilde{g}^{y_1}, ..., \tilde{g}^{y_{r+1}})
        GroupElementVector group2ElementsTildeYi = GroupElementVector.fromStream(Arrays.stream(exponentsYi)
                .map(group2ElementTildeG::pow));


        // Precompute for bases in multi-exponentiation
        group2ElementTildeX.precomputePow();
        group2ElementsTildeYi.map(GroupElement::precomputePow);

        // Construct secret signing key
        PS18SigningKey sk = new PS18SigningKey(exponentX, exponentsYi);

        // Construct public verification key
        PS18VerificationKeyVector pk = new PS18VerificationKeyVector(
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

        if (messageBlock.size() != sk.getNumberOfMessages()) {
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
        if (!(publicKey instanceof PS18VerificationKeyVector)) {
            throw new IllegalArgumentException("Public key is not a 'PS18VerificationKey' " +
                    "instance.");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        PS18VerificationKeyVector pk = (PS18VerificationKeyVector) publicKey;
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
            resultExponent = resultExponent.add(sk.getExponentsYi()[i].mul(messageElement));
        }
        resultExponent = resultExponent.add(
                sk.getExponentsYi()[sk.getNumberOfMessages()].mul(exponentPrimeM)
        );
        // Now we exponentiate h with the exponent and return that as sigma_2.
        return sigma1.pow(resultExponent.getInteger());
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
    protected GroupElement computeLeftHandSide(MessageBlock messageBlock, PS18VerificationKeyVector pk,
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
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return mapToPlaintext(bytes, ((PS18VerificationKeyVector) pk).getNumberOfMessages());
    }

    @Override
    public VerificationKey getVerificationKey(Representation repr) {
        return new PS18VerificationKeyVector(repr, this.pp.getBilinearMap().getG2());
    }
}
