package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.signature.SignatureKeyPair;
import de.upb.crypto.craco.interfaces.signature.SignatureScheme;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.craco.sig.ps.PSSignatureScheme;

import java.util.Arrays;

/**
 * Extension of the implementation of the Signature scheme that was originally presented in chapter 4.2 of [1] by
 * Pointcheval and Sanders. The result is a block signature scheme.
 * <p>
 * The signing key remains the same, but the verification key is extended to store the generator g and the
 * group-elements Y-i from group 1. The extended implementation of the
 * {@link PSSignatureScheme}
 * allows the usage of the {@link PSExtendedVerificationKey} containing the generator g and the
 * group-elements Y-i from group 1 and enable 'signing messages blindly'
 * when used in a {@link PedersenCommitmentScheme}:
 * it allows for being able to blind and unblind messages before and after signing them. This is
 * achieved by using the same g and Y-i in the
 * {@link PedersenPublicParameters} as provided by the
 * {@link PSExtendedSignatureScheme}. This case allows a user to receive a signature on a commitment for a message and
 * to then calculate the signature for the uncommited message and thereby receiving a signature of a signer for a
 * message without the signer knowing the content of the message.
 * <p>
 * Bilinear map type: 3
 *
 * <p>
 * [1] David Pointcheval and Olivier Sanders, Short Randomizable Signatures, in Cryptology ePrint Archive,
 * Report 2015/525, 2015.
 * </p>
 */
public class PSExtendedSignatureScheme extends de.upb.crypto.craco.sig.ps.PSSignatureScheme implements SignatureScheme {

    public PSExtendedSignatureScheme(PSPublicParameters pp) {
        super(pp);
    }

    public PSExtendedSignatureScheme(Representation rep) {
        super(rep);
    }

    /**
     * Using the {@link PSPublicParameters} first a {@link SignatureKeyPair} consisting of a
     * {@link PSSigningKey} and a {@link PSVerificationKey} (with respect to the given
     * security parameter securityParameter and the block size numberOfMessages of the signature scheme - normal key
     * generation) are generated. Using this {@link SignatureKeyPair} and the {@link PSPublicParameters}of this
     * {@link PSExtendedSignatureScheme} the generator g and the group-elements Y-i from group 1 are generated and then
     * stored in a new {@link SignatureKeyPair} containing the new {@link PSExtendedVerificationKey} key.
     * This key pair is then returned.
     *
     * @param numberOfMessages The block size of the signature scheme.
     * @return A key pair of the {@link PSExtendedVerificationKey} and
     * {@link PSSigningKey} for a {@link PSExtendedSignatureScheme}.
     */
    @Override
    public SignatureKeyPair<? extends PSExtendedVerificationKey, ? extends PSSigningKey> generateKeyPair(
            int numberOfMessages) {
        // Generate a normal key pair for a Pointcheval Sanders signature scheme
        SignatureKeyPair<? extends PSVerificationKey, ? extends PSSigningKey> shortKey =
                super.generateKeyPair(numberOfMessages);
        // Compute the generator g and the group-elements Y-i from group 1
        // g for enabling optional blinding/unblinding; g must not be the neutral element
        GroupElement group1ElementG = getPp().getBilinearMap().getG1().getGenerator();
        // Y_i enabling optional blinding/unblinding
        GroupElement[] group1ElementsYi = Arrays.stream(shortKey.getSigningKey().getExponentsYi())
                .map(group1ElementG::pow).toArray(GroupElement[]::new);

        // Set the extended verification key for a Pointcheval Sanders signature scheme
        final PSVerificationKey shortVerificationKey = shortKey.getVerificationKey();
        PSExtendedVerificationKey extendedVerificationKey = new PSExtendedVerificationKey(group1ElementG,
                group1ElementsYi, shortVerificationKey.getGroup2ElementTildeG(),
                shortVerificationKey.getGroup2ElementTildeX(), shortVerificationKey.getGroup2ElementsTildeYi());

        // Return a new key pair containing the new extended Verification key for a Pointcheval Sanders signature scheme
        return new SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey>(extendedVerificationKey,
                shortKey.getSigningKey());
    }

    /**
     * Method to recreate an extended verification key for a Pointcheval Signature Scheme from its representation.
     *
     * @param repr Representation of an extended verification key for a Pointcheval Signature Scheme
     * @return An extended verification key for a Pointcheval Signature Scheme
     */
    @Override
    public PSExtendedVerificationKey getVerificationKey(Representation repr) {
        final BilinearMap bilinearMap = super.getPp().getBilinearMap();
        // Constructor for using the extended Verification key (enabling optional blinding/unblinding)
        return new PSExtendedVerificationKey(bilinearMap.getG1(), bilinearMap.getG2(), repr);
    }

    /**
     * Randomizes a signature based on the given randomness.
     *
     * @param signature The signature which should be randomized
     * @param random    A uniformly random picked element used to randomize the signature.
     *                  This element is needed to prove the actual knowledge of the signature.
     * @return Randomized variant of the original signature
     */
    public PSSignature randomizeExistingSignature(PSSignature signature, Zp.ZpElement random) {
        // u is an unit from ZP
        Zp.ZpElement u = getPp().getZp().getUniformlyRandomUnit();

        GroupElement sigma1 = signature.getGroup1ElementSigma1();
        GroupElement sigma2 = signature.getGroup1ElementSigma2();

        // Calculate the randomized signature (o_1', o_2') = ((o_1)^u,(o_2 (o_1)^r)^u)
        GroupElement sigma1prime = sigma1.pow(u);
        GroupElement sigma2prime = sigma2.op(sigma1.pow(random)).pow(u);

        return new PSSignature(sigma1prime, sigma2prime);
    }

    /**
     * Generates a blinded signature where the blindingElement is used as the first message element, followed by an
     * usual list of {@link PlainText} elements
     *
     * @param signingKey      The {@link PSSigningKey}
     * @param verificationKey The {@link PSExtendedVerificationKey}
     * @param blindingElement The element which contains the randomness in the format of
     *                        <code>group1ElementG.pow(blindingRandomness).op(Y0.pow(valueToBlind))</code>
     * @param message         The messages which should be signed in addition to the blinded value
     * @return A blinded {@link PSSignature} which can be unblinded using
     * {@link PSExtendedSignatureScheme#unblindSignature(PSSignature, Zp.ZpElement)}
     */
    public PSSignature blindSign(PSSigningKey signingKey, PSExtendedVerificationKey verificationKey,
                                 GroupElement blindingElement, PlainText message) {
        MessageBlock messageBlock = (MessageBlock) message;
        if (messageBlock.size() != verificationKey.getGroup1ElementsYi().length - 1) {
            throw new IllegalArgumentException("Expected 'message' to be one less than the number of messages of an " +
                    "ordinary signature");
        }

        Zp zp = getPp().getZp();
        Zp.ZpElement u = zp.getUniformlyRandomElement();

        // Calculating the signature
        final GroupElement g1 = verificationKey.getGroup1ElementG();
        GroupElement sigma1 = g1.pow(u);
        final Zp.ZpElement signingKeyX = signingKey.getExponentX();
        GroupElement sigma2 = g1.pow(signingKeyX).op(blindingElement);
        for (int i = 0; i < messageBlock.size(); ++i) {
            final GroupElement group1YiElement = verificationKey.getGroup1ElementsYi()[i + 1];
            RingElementPlainText ringElement = (RingElementPlainText) messageBlock.get(i);
            Zp.ZpElement zpMessageElement = (Zp.ZpElement) ringElement.getRingElement();
            sigma2 = sigma2.op(group1YiElement.pow(zpMessageElement));
        }
        sigma2 = sigma2.pow(u);
        return new PSSignature(sigma1, sigma2);
    }

    /**
     * Unblinds a signature which was previously blinded using
     * {@link PSExtendedSignatureScheme#blindSign(PSSigningKey, PSExtendedVerificationKey, GroupElement, PlainText)}
     *
     * @param signature          The blinded {@link PSSignature}
     * @param blindingRandomness The <code>blindingRandomness</code> of the
     *                           <code>group1ElementG.pow(blindingRandomness).op(Y0.pow(valueToBlind))</code> element
     *                           which was used for blinding
     * @return An unblinded {@link PSSignature}
     */
    public PSSignature unblindSignature(PSSignature signature, Zp.ZpElement blindingRandomness) {
        final GroupElement sigma1 = signature.getGroup1ElementSigma1();
        final GroupElement sigma2 = signature.getGroup1ElementSigma2();
        final GroupElement unblindedSigma2 = sigma2.op(sigma1.pow(blindingRandomness).inv());
        return new PSSignature(sigma1, unblindedSigma2);
    }
}
