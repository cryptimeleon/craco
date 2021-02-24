package org.cryptimeleon.craco.sig.ps;

import org.cryptimeleon.craco.commitment.pedersen.PedersenCommitmentScheme;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.cartesian.GroupElementVector;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;

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
 * {@link PedersenCommitmentScheme} as provided by the
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
public class PSExtendedSignatureScheme extends PSSignatureScheme{

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
    public SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> generateKeyPair(int numberOfMessages) {
        // Generate a normal key pair for a Pointcheval Sanders signature scheme
        SignatureKeyPair<? extends PSVerificationKey, ? extends PSSigningKey> shortKey =
                super.generateKeyPair(numberOfMessages);
        // Compute the generator g and the group-elements Y-i from group 1
        // g for enabling optional blinding/unblinding; g must not be the neutral element
        GroupElement group1ElementG = getPp().getBilinearMap().getG1().getGenerator();
        // Y_i enabling optional blinding/unblinding
        GroupElementVector group1ElementsYi = group1ElementG.pow(shortKey.getSigningKey().getExponentsYi());

        // Set the extended verification key for a Pointcheval Sanders signature scheme
        final PSVerificationKey shortVerificationKey = shortKey.getVerificationKey();
        PSExtendedVerificationKey extendedVerificationKey = new PSExtendedVerificationKey(group1ElementG,
                group1ElementsYi, shortVerificationKey.getGroup2ElementTildeG(),
                shortVerificationKey.getGroup2ElementTildeX(), shortVerificationKey.getGroup2ElementsTildeYi());

        // Return a new key pair containing the new extended Verification key for a Pointcheval Sanders signature scheme
        return new SignatureKeyPair<>(extendedVerificationKey, shortKey.getSigningKey());
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
}
