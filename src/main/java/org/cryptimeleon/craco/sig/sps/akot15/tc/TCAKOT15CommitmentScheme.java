package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.*;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.sps.SPSMessageSpaceVerifier;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.pos.*;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.*;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.RepresentableRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Arrays;
import java.util.Objects;

/**
 * An implementation of the structure preserving commitment scheme TC presented in [1]
 * While the scheme is intended to be a building block of the larger SPS scheme
 * {@link org.cryptimeleon.craco.sig.sps.akot15.fsp2.SPSFSP2SignatureScheme},
 * the implementation can be used on its own, where it is chosen message target collision resistant
 * under the assumptions that its building blocks {@link SPSPOSSignatureScheme}
 * and {@link TCGAKOT15CommitmentScheme} make.
 *
 * Note: While the scheme is a trapdoor commitment scheme in the paper, its trapdoor functionality (SimCom, Equiv in
 * the paper) has been omitted for this implementation, as it is not required for FSPS2 to work as intended.
 *
 * Note: This scheme does not possess its own implementation of an {@link Commitment} instance. It instead reuses
 * {@link TCGAKOT15Commitment}, as the paper states com := com_gbc
 *
 *
 * [1] Abe et al.: Fully Structure-Preserving Signatures and Shrinking Commitments.
 * https://eprint.iacr.org/2015/076.pdf
 *
 */
public class TCAKOT15CommitmentScheme implements CommitmentScheme, SPSMessageSpaceVerifier {

    /**
     * The public parameters used by this scheme
     */
    @Represented
    AKOT15SharedPublicParameters pp;

    /**
     * An instance of {@link SPSPOSSignatureScheme} used for commitment calculation
     */
    @Represented
    SPSPOSSignatureScheme posInstance;

    /**
     * An instance of {@link TCGAKOT15CommitmentScheme} used for commitment calculation
     */
    @Represented
    TCGAKOT15CommitmentScheme gbcInstance;

    /**
     * In order to match the {@link CommitmentScheme} interface, the scheme stores its own keys
     * instead of the key passed as a parameter of commit() / verify().
     */
    @Represented
    TCGAKOT15CommitmentKey commitmentKey;

    /**
     * Instead of running several instances of {@link SPSPOSSignatureScheme}, the scheme calculates its own one-time
     *      keys and passes each of them to a single {@code posInstance} in sequence.
     */
    //@Represented(restorer = "[Zp]")
    ZpElement[] oneTimeSecretKeys;

    /**
     * Instead of running several instances of {@link SPSPOSSignatureScheme}, the scheme calculates its own one-time
     *      keys and passes each of them to a single {@code posInstance} in sequence.
     */
    //@Represented(restorer = "[G1]")
    GroupElement[] oneTimePublicKeys;


    public TCAKOT15CommitmentScheme(AKOT15SharedPublicParameters pp) {
        super();
        this.pp = pp;

        AKOT15SharedPublicParameters pp_pos = pp.clone();
        pp_pos.setMessageLength(1);

        //create nested signature scheme instance (using the same public parameters)
        this.posInstance = new SPSPOSSignatureScheme(pp_pos);

        // as tc gamma will sign the verification key of posInstance, its expected messages are 2 elements longer
        AKOT15SharedPublicParameters pp_gbc = pp.clone();
        pp_gbc.setMessageLength(pp.getMessageLength() + 2);

        this.gbcInstance = new TCGAKOT15CommitmentScheme(pp_gbc);

        this.commitmentKey = generateKey();
    }

    /**
     * Set up the scheme using a set of shared parameters, as well as special parameters for TC gamma, enabling
     *      inter-compatibility with {@link org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGSignatureScheme}
     *
     * Note: The original paper contains a typo in the section: "Procedure: Matching C_gbc to M_xsig -- Setup" [1, p.17]
     *       The whole of TC must be initialized with F_1, F^{tilde}_1 as the default generators, not just TC_gamma.
     */
    public TCAKOT15CommitmentScheme(AKOT15SharedPublicParameters sharedPublicParametersParameters,
                                    TCGAKOT15XSIGPublicParameters tcGammaPublicParameters) {
        super();

        // set up general PublicParameters for this scheme
        this.pp = new AKOT15SharedPublicParameters(
                sharedPublicParametersParameters.getBilinearGroup(),
                sharedPublicParametersParameters.getMessageLength(),
                tcGammaPublicParameters.getG1GroupGenerator(),
                tcGammaPublicParameters.getG2GroupGenerator());

        // set up POS specific public parameters
        AKOT15SharedPublicParameters pp_pos = new AKOT15SharedPublicParameters(
                sharedPublicParametersParameters.getBilinearGroup(),
                1,
                tcGammaPublicParameters.getG1GroupGenerator(),
                tcGammaPublicParameters.getG2GroupGenerator());

        //create nested signature scheme instance (using the same public parameters)
        this.posInstance = new SPSPOSSignatureScheme(pp_pos);

        // use a special set of public parameters for tc_gamma if given (these are to be provided by FSP2)
        this.gbcInstance = new TCGAKOT15CommitmentScheme(tcGammaPublicParameters);

        this.commitmentKey = generateKey();
    }

    public TCAKOT15CommitmentScheme(Representation repr) {

        super();

        // manually deserialize the scheme

        ObjectRepresentation objRepr = (ObjectRepresentation) repr;

        this.pp = new AKOT15SharedPublicParameters(((RepresentableRepresentation)objRepr.get("pp")).getRepresentation());
        this.posInstance = new SPSPOSSignatureScheme(((RepresentableRepresentation)objRepr.get("posInstance")).getRepresentation());
        this.gbcInstance = new TCGAKOT15CommitmentScheme(((RepresentableRepresentation)objRepr.get("gbcInstance")).getRepresentation());

        if(((RepresentableRepresentation)objRepr.get("commitmentKey")).getRepresentedTypeName()
                .equals(TCGAKOT15XSIGCommitmentKey.class.getName())) {
            this.commitmentKey = new TCGAKOT15XSIGCommitmentKey(pp.getG2GroupGenerator().getStructure(),
                    ((RepresentableRepresentation)objRepr.get("commitmentKey")).getRepresentation());
        }
        else {
            this.commitmentKey = new TCGAKOT15CommitmentKey(pp.getG2GroupGenerator().getStructure(),
                    ((RepresentableRepresentation)objRepr.get("commitmentKey")).getRepresentation());
        }

        // the one-time keys need not be represented, as they are only generated upon committing;
    }


    public TCGAKOT15CommitmentKey generateKey() {
        return gbcInstance.getCommitmentKey();
    }


    @Override
    public CommitmentPair commit(PlainText plainText) {
        return commit(plainText, commitmentKey);
    }

    public CommitmentPair commit(PlainText plainText, CommitmentKey commitmentKey) {

        if(!(commitmentKey instanceof TCGAKOT15CommitmentKey)) {
            throw new IllegalArgumentException("This is not a valid commitment key for this scheme");
        }

        //if plainText contains only a single group element, wrap it in a MessageBlock
        if((plainText instanceof GroupElementPlainText)) {
            plainText = new MessageBlock(plainText);
        }

        // check if the plainText matches the structure expected by the scheme. It should be a MessageBlock composed
        //      of GroupElements in G_2
        doMessageChecks(plainText, pp.getMessageLength(), pp.getG2GroupGenerator().getStructure());

        MessageBlock messageBlock = (MessageBlock) plainText;
        TCGAKOT15CommitmentKey ck = (TCGAKOT15CommitmentKey) commitmentKey;

        SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey> posKeyPair =
                (SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) posInstance.generateKeyPair();
        generateOneTimeKeys();

        SPSPOSSignature[] sigmas = new SPSPOSSignature[pp.getMessageLength()];

        for (int i = 0; i < sigmas.length; i++) {
            sigmas[i] = posInstance.sign(new MessageBlock(messageBlock.get(i)), posKeyPair.getSigningKey(), oneTimeSecretKeys[i]);
        }

        RingElementPlainText[] msg_com = new RingElementPlainText[pp.getMessageLength() + 2];

        msg_com[0] = new RingElementPlainText(posKeyPair.getSigningKey().getExponentW());
        msg_com[1] = new RingElementPlainText(posKeyPair.getSigningKey().getExponentsChi()[0]);

        for (int i = 2; i < msg_com.length; i++) {
            msg_com[i] = new RingElementPlainText(oneTimeSecretKeys[i - 2]);
        }

        // commit using TC_gamma
        CommitmentPair gbcCommitmentPair = gbcInstance.commit(new MessageBlock(msg_com));

        TCAKOT15OpenValue open = new TCAKOT15OpenValue(
                ((TCGAKOT15OpenValue)gbcCommitmentPair.getOpenValue()).getGroup1ElementR(),
                posKeyPair.getVerificationKey(),
                oneTimePublicKeys,
                sigmas
        );

        return new CommitmentPair(gbcCommitmentPair.getCommitment(), open);
    }

    /**
     * Instead of running several instances of {@link SPSPOSSignatureScheme}, the scheme calculates its own one-time
     *      keys and passes each of them to a single {@code posInstance} in sequence.
     *
     * The individual one-time keys are generated the same way as in {@link SPSPOSSignatureScheme}.
     */
    private void generateOneTimeKeys() {
        oneTimeSecretKeys = new ZpElement[pp.getMessageLength()];
        oneTimePublicKeys = new GroupElement[pp.getMessageLength()];

        for (int i = 0; i < oneTimePublicKeys.length; i++) {
            oneTimeSecretKeys[i] = pp.getZp().getUniformlyRandomNonzeroElement();
            oneTimePublicKeys[i] = pp.getG1GroupGenerator().pow(oneTimeSecretKeys[i]).compute();
        }
    }

    @Override
    public boolean verify(Commitment commitment, OpenValue openValue, PlainText plainText) {
        return verify(plainText, commitmentKey, commitment, openValue);
    }

    public boolean verify(PlainText plainText, CommitmentKey commitmentKey, Commitment commitment, OpenValue openValue) {

        if(!(commitmentKey instanceof TCGAKOT15CommitmentKey)) {
            throw new IllegalArgumentException("This is not a valid commitment key for this scheme");
        }

        if(!(commitment instanceof TCGAKOT15Commitment)) {
            throw new IllegalArgumentException("This is not a valid commitment for this scheme");
        }

        if(!(openValue instanceof TCAKOT15OpenValue)) {
            throw new IllegalArgumentException("This is not a valid commitment for this scheme");
        }

        //if plainText contains only a single group element, wrap it in a MessageBlock
        if((plainText instanceof GroupElementPlainText)) {
            plainText = new MessageBlock(plainText);
        }

        // check if the plainText matches the structure expected by the scheme. It should be a MessageBlock composed
        //      of GroupElements in G_2
        doMessageChecks(plainText, pp.getMessageLength(), pp.getG2GroupGenerator().getStructure());

        MessageBlock messageBlock = (MessageBlock) plainText;
        TCGAKOT15Commitment com = (TCGAKOT15Commitment) commitment;
        TCAKOT15OpenValue open = (TCAKOT15OpenValue) openValue;

        for (int i = 0; i < messageBlock.length(); i++) {

            if( !posInstance.verify(new MessageBlock(
                    messageBlock.get(i)),
                    open.getSpsPosSignatures()[i],
                    open.spsPosVerificationKey, oneTimePublicKeys[i])) {
                return false;
            }
        }

        GroupElementPlainText[] msg_com = new GroupElementPlainText[pp.getMessageLength() + 2];

        msg_com[0] = new GroupElementPlainText(open.getSpsPosVerificationKey().getGroup1ElementW());
        msg_com[1] = new GroupElementPlainText(open.getSpsPosVerificationKey().getGroup1ElementsChi()[0]);

        for (int i = 2; i < msg_com.length; i++) {
            msg_com[i] = new GroupElementPlainText(oneTimePublicKeys[i - 2]);
        }

        return gbcInstance.verify(com, new TCGAKOT15OpenValue(open.getGroup1ElementGamma()), new MessageBlock(msg_com));
    }


    @Override
    public MessageBlock mapToPlaintext(byte[] bytes) {
        // returns (P^m, P, ..., P) where m = Z_p.injectiveValueOf(bytes).

        GroupElementPlainText[] msgBlock = new GroupElementPlainText[pp.getMessageLength()];
        msgBlock[0] = new GroupElementPlainText(
                pp.getG2GroupGenerator().pow(pp.getZp().injectiveValueOf(bytes))
        );
        for (int i = 1; i < pp.getMessageLength(); i++) {
            msgBlock[i] = new GroupElementPlainText(pp.getG2GroupGenerator());
        }

        return new MessageBlock(msgBlock);
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return (pp.getG1GroupGenerator().getStructure().size().bitLength() - 1) / 8;
    }

    @Override
    public Commitment restoreCommitment(Representation repr) {
        return new TCGAKOT15Commitment(pp.getG2GroupGenerator().getStructure(), repr);
    }

    @Override
    public OpenValue restoreOpenValue(Representation repr) {
        return new TCAKOT15OpenValue(
                pp.getG1GroupGenerator().getStructure(),
                pp.getG2GroupGenerator().getStructure(),
                repr);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation objRepr = (ObjectRepresentation) new ReprUtil(this).serialize();

        // store specific class of commitment key
        objRepr.put("commitmentKey", new RepresentableRepresentation(commitmentKey));

        return objRepr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TCAKOT15CommitmentScheme that = (TCAKOT15CommitmentScheme) o;
        return Objects.equals(pp, that.pp)
                && Objects.equals(posInstance, that.posInstance)
                && Objects.equals(gbcInstance, that.gbcInstance)
                && Objects.equals(commitmentKey, that.commitmentKey)
                && Arrays.equals(oneTimeSecretKeys, that.oneTimeSecretKeys)
                && Arrays.equals(oneTimePublicKeys, that.oneTimePublicKeys);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(pp, posInstance, gbcInstance, commitmentKey);
        result = 31 * result + Arrays.hashCode(oneTimeSecretKeys);
        result = 31 * result + Arrays.hashCode(oneTimePublicKeys);
        return result;
    }

}
