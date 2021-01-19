package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.sig.interfaces.Signature;
import de.upb.crypto.craco.sig.interfaces.SigningKey;
import de.upb.crypto.craco.sig.interfaces.VerificationKey;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
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
 *
 */
public class PS18ROMSignatureScheme extends PS18SignatureScheme {

    public PS18ROMSignatureScheme(PSPublicParameters pp) {
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
                .getUniformlyRandomNonNeutral().compute();

        // m' in Z_p, computed as hash of messages
        ZpElement exponentPrimeM = romHashIntoZp(messageBlock, zp);

        // Compute second element of signature
        PS18SignatureScheme ps18SigScheme = new PS18SignatureScheme(pp);
        GroupElement group1ElementSigma2 = ps18SigScheme.computeSigma2(
                messageBlock, sk, exponentPrimeM, group1ElementSigma1
        ).compute();
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

        PS18SignatureScheme ps18SigScheme = new PS18SignatureScheme(pp);
        leftHandSide = ps18SigScheme.computeLeftHandSide(
                messageBlock, pk, romHashIntoZp(messageBlock, zp), sigma.getGroup1ElementSigma1()
        );

        return leftHandSide.equals(rightHandSide);
    }

    @Override
    public Signature getSignature(Representation repr) {
        return new PS18ROMSignature(repr, this.pp.getBilinearMap().getG1());
    }

    private ZpElement romHashIntoZp(MessageBlock messages, Zp zp) {
        byte[] messageBytes = messages.getUniqueByteRepresentation();

        return new HashIntoZp(zp).hashIntoStructure(messageBytes);
    }
}
