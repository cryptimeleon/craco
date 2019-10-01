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
                        String.format("%d'th message element is not an 'RingElementPlainText' instance.", i)
                );
            } else if () {
                throw 
            }
            ZpElement messageElement = (ZpElement) ((RingElementPlainText) messagePartI).getRingElement();
        }
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {
        return null;
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return null;
    }

    @Override
    public Signature getSignature(Representation repr) {
        return null;
    }

    @Override
    public SigningKey getSigningKey(Representation repr) {
        return null;
    }

    @Override
    public VerificationKey getVerificationKey(Representation repr) {
        return null;
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, VerificationKey pk) {
        return null;
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes, SigningKey sk) {
        return null;
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return 0;
    }

    @Override
    public Representation getRepresentation() {
        return null;
    }
}
