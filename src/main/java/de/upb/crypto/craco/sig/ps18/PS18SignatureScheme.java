package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.signature.*;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.stream.IntStream;


public class PS18SignatureScheme implements StandardMultiMessageSignatureScheme {

    /**
     * pp in paper. Public parameters of the signature scheme.
     */
    @Represented
    private PS18PublicParameters pp;

    public PS18SignatureScheme(PS18PublicParameters pp) {
        this.pp = pp;
    }

    public PS18SignatureScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public SignatureKeyPair<? extends VerificationKey, ? extends SigningKey>
    generateKeyPair(int numberOfMessages) {
        // get exponent field and store group2 for shorter usage
        Group group2 = pp.getBilinearMap().getG2();
        Zp zp = pp.getZp();

        // Pick \tilde{g} from G_2^*
        GroupElement group2ElementTildeG = group2.getUniformlyRandomNonNeutral();
        // Pick x from Z_p^*
        ZpElement exponentX = zp.getUniformlyRandomUnit();
        // Pick y_1, ..., y_{r+1} from Z_p^* (r is number of messages)
        ZpElement[] exponentsYi = IntStream.range(0, numberOfMessages+1)
                .mapToObj(a -> zp.getUniformlyRandomUnit())
                .toArray(ZpElement[]::new);

        // Compute \tilde{X} = \tilde{g}^x
        GroupElement group2ElementTildeX = group2ElementTildeG.pow(exponentX);
        // Compute (\tilde{Y_1}, ..., \tilde{Y_{r+1}}) = (\tilde{g}^{y_1}, ..., \tilde{g}^{y_{r+1}})
        GroupElement[] group2ElementsTildeYi = Arrays.stream(exponentsYi)
                .map(group2ElementTildeG::pow)
                .toArray(GroupElement[]::new);

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

        if (messageBlock.size() != sk.getNumberOfMessages()) {
            throw new IllegalArgumentException("Message length does not match length " +
                    "supported by signing key.");
        }
        // we use this twice so generate only once here
        Zp zp = pp.getZp();

        // h in G_1^*, second element of signature
        GroupElement group1ElementH = pp.getBilinearMap().getG1().getUniformlyRandomNonNeutral();

        // m' in Z_p, first element of signature
        ZpElement exponentPrimeM = zp.getUniformlyRandomElement();

        // Compute third element of signature
        // First we compute the exponent = x + \sum_{i=1}{r}{y_i * m_i} + y_{r+1} * m'
        ZpElement resultExponent = sk.getExponentX();
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
            ZpElement messageElement = (ZpElement) messageRingElement.getRingElement();
            resultExponent = resultExponent.add(sk.getExponentsYi()[i].mul(messageElement));
        }
        resultExponent = resultExponent.add(
                sk.getExponentsYi()[sk.getNumberOfMessages()].mul(exponentPrimeM)
        );
        // Now we exponentiate h with the exponent.
        GroupElement group1ElementSigma3 = group1ElementH.pow(resultExponent.getInteger());

        return new PS18Signature(exponentPrimeM, group1ElementH, group1ElementSigma3);
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
            throw new IllegalArgumentException("Public key is not a 'PS18VerificationKey' instance.");
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

        // Computation of group element from G_2 for left hand side requires sum
        // \tilde{x} * \prod_{i=1}{r}{\tilde{Y_i}^{m_i}} * \tilde{Y}_{r+1}^{m'}
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
                        String.format("%d'th message element is not a 'RingElementPlainText' instance.", i)
                );
            }
            RingElementPlainText messageRingElement = (RingElementPlainText) messagePartI;
            if (!(messageRingElement.getRingElement().getStructure().equals(pp.getZp()))) {
                throw new IllegalArgumentException(
                        String.format("%d'th message element is not an element of Zp.", i)
                );
            }
            ZpElement messageElement = (ZpElement) messageRingElement.getRingElement();
            leftGroup2Elem.op(pk.getGroup2ElementsTildeYi()[i].pow(messageElement));
        }
        leftGroup2Elem.op(
                pk.getGroup2ElementsTildeYi()[pk.getNumberOfMessages()].pow(sigma.getExponentPrimeM())
        );

        leftHandSide = pp.getBilinearMap().apply(sigma.getGroup1ElementSigma1(), leftGroup2Elem);

        return leftHandSide.equals(rightHandSide);
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new MessageBlock(repr, RingElementPlainText::new);
    }

    @Override
    public Signature getSignature(Representation repr) {
        return new PS18Signature(repr, this.pp.getZp(), this.pp.getBilinearMap().getG1());
    }

    @Override
    public SigningKey getSigningKey(Representation repr) {
        return new PS18SigningKey(repr, this.pp.getZp());
    }

    @Override
    public VerificationKey getVerificationKey(Representation repr) {
        return new PS18VerificationKey(repr, this.pp.getBilinearMap().getG2());
    }

    public PS18PublicParameters getPp() {
        return pp;
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return mapToPlaintext(bytes, ((PS18VerificationKey) pk).getNumberOfMessages());
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        return mapToPlaintext(bytes, ((PS18SigningKey) sk).getNumberOfMessages());
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getZp().size().bitLength() - 1) / 8;
    }

    private MessageBlock mapToPlaintext(byte[] bytes, int messageBlockLength) {
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
        PS18SignatureScheme other = (PS18SignatureScheme) obj;
        if (pp == null) {
            return other.pp == null;
        } else return pp.equals(other.pp);
    }
}
