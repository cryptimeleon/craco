package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.interfaces.signature.SigningKey;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

/**
 * This class implements the signature scheme from Pointcheval and Sanders 2018 in
 * section 4.3 where the extra m' element is computed from the message in the
 * random oracle model. This saves one Z_p element for the signature.
 * However, the reduction adversary has to also guess in which random oracle
 * query the right message is, so the reduction loses a poly factor in success probability.
 *
 * @author Raphael Heitjohann
 */
public class PS18ROMSignatureScheme extends PS18SignatureScheme {

    public PS18ROMSignatureScheme(PS18PublicParameters pp) {
        super(pp);
    }

    public PS18ROMSignatureScheme(Representation repr) {
        super(repr);
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

        // m' in Z_p, computed as hash of messages
        ZpElement exponentPrimeM = romHashIntoZp(messageBlock, zp);

        // Compute third element of signature
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
            if (!(messageRingElement.getRingElement().getStructure().equals(zp))) {
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
        // Now we exponentiate h with the exponent.
        GroupElement group1ElementSigma2 = group1ElementSigma1.pow(resultExponent.getInteger());

        // TODO: We could also just resue the PSSignature,
        //  but that does use old representation.
        return new PS18ROMSignature(group1ElementSigma1, group1ElementSigma2);
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
        if (!(signature instanceof PS18ROMSignature)) {
            throw new IllegalArgumentException("Signature is not a 'PS18Signature' instance.");
        }
        if (!(publicKey instanceof PS18VerificationKey)) {
            throw new IllegalArgumentException("Public key is not a 'PS18VerificationKey' " +
                    "instance.");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        PS18VerificationKey pk = (PS18VerificationKey) publicKey;
        PS18ROMSignature sigma = (PS18ROMSignature) signature;

        // Check that groupElementSigma1 is not neutral element of G_1
        if (sigma.getGroup1ElementSigma1().isNeutralElement())
            return false;

        Zp zp = pp.getZp();

        // Check that bilinear pairing equation holds
        GroupElement leftHandSide, rightHandSide;

        rightHandSide = pp.getBilinearMap().apply(
                sigma.getGroup1ElementSigma2(), pk.getGroup2ElementTildeG()
        );

        // Computation of group element from G_2 for left hand side requires sum
        // \tilde{X} * \prod_{i=1}{r}{\tilde{Y_i}^{m_i}} * \tilde{Y}_{r+1}^{m'}
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
            if (!(messageRingElement.getRingElement().getStructure().equals(zp))) {
                throw new IllegalArgumentException(
                        String.format("%d'th message element is not an element of Zp.", i)
                );
            }
            Zp.ZpElement messageElement = (Zp.ZpElement) messageRingElement.getRingElement();
            leftGroup2Elem = leftGroup2Elem.op(
                    pk.getGroup2ElementsTildeYi()[i].pow(messageElement)
            );
        }
        leftGroup2Elem = leftGroup2Elem.op(
                pk.getGroup2ElementsTildeYi()[pk.getNumberOfMessages()]
                        .pow(romHashIntoZp(messageBlock, zp))
        );

        leftHandSide = pp.getBilinearMap().apply(sigma.getGroup1ElementSigma1(), leftGroup2Elem);

        return leftHandSide.equals(rightHandSide);
    }

    @Override
    public Signature getSignature(Representation repr) {
        return new PS18ROMSignature(repr, this.pp.getBilinearMap().getG1());
    }

    private ZpElement romHashIntoZp(MessageBlock messages, Zp zp) {
        // TODO: this correct?
        byte[] messageBytes = messages.getUniqueByteRepresentation();

        return new HashIntoZp(zp).hashIntoStructure(messageBytes);
    }
}
