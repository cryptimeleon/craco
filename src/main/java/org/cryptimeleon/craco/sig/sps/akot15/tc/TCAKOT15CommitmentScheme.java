package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.*;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.pos.*;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.*;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.SPSXSIGPublicParameters;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

public class TCAKOT15CommitmentScheme implements CommitmentScheme {

    @Represented
    AKOT15SharedPublicParameters pp;

    SPSPOSSignatureScheme posInstance;
    TCGAKOT15CommitmentScheme gbcInstance;

    TCGAKOT15CommitmentKey commitmentKey;

    ZpElement[] oneTimeSecretKeys;
    GroupElement[] oneTimePublicKeys;

    MessageBlock commitMsg;

    //TODO set these up better

    private GroupElement getG1GroupGenerator() {
        return (pp instanceof SPSXSIGPublicParameters) ? ((SPSXSIGPublicParameters)pp).getGroup1ElementF1() : pp.getG1GroupGenerator();
    }

    private GroupElement getG2GroupGenerator() {
        return (pp instanceof SPSXSIGPublicParameters) ? ((SPSXSIGPublicParameters)pp).getGroup2ElementF1() : pp.getG2GroupGenerator();
    }

    public TCAKOT15CommitmentScheme(AKOT15SharedPublicParameters pp) {
        super();
        this.pp = pp;

        AKOT15SharedPublicParameters pp_pos = pp.clone();
        pp_pos.setMessageLength(1);

        //create nested signature scheme instance (using the same public parameters)
        this.posInstance = new SPSPOSSignatureScheme(pp_pos);

        // as tc gamma will sign the verification key of posInstance, it's expected messages are 2 elements longer
        AKOT15SharedPublicParameters pp_gbc = pp.clone();
        pp_gbc.setMessageLength(pp.getMessageLength() + 2);

        this.gbcInstance = new TCGAKOT15CommitmentScheme(pp_gbc);

        this.commitmentKey = generateKey();
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

        if(!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("This is not a valid message for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        TCGAKOT15CommitmentKey ck = (TCGAKOT15CommitmentKey) commitmentKey;

        SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey> posKeyPair = (SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey>) posInstance.generateKeyPair();
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

        commitMsg = new MessageBlock(msg_com);

        CommitmentPair gbcCommitmentPair = gbcInstance.commit(commitMsg);

        TCAKOT15OpenValue open = new TCAKOT15OpenValue(
                ((TCGAKOT15OpenValue)gbcCommitmentPair.getOpenValue()).getGroup1ElementR(),
                posKeyPair.getVerificationKey(),
                oneTimePublicKeys,
                sigmas
        );

        return new CommitmentPair(gbcCommitmentPair.getCommitment(), open);
    }


    private void generateOneTimeKeys() {
        oneTimeSecretKeys = new ZpElement[pp.getMessageLength()];
        oneTimePublicKeys = new GroupElement[pp.getMessageLength()];

        for (int i = 0; i < oneTimePublicKeys.length; i++) {
            oneTimeSecretKeys[i] = pp.getZp().getUniformlyRandomNonzeroElement();
            oneTimePublicKeys[i] = getG1GroupGenerator().pow(oneTimeSecretKeys[i]).compute();
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

        if(!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("This is not a valid message for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        TCGAKOT15CommitmentKey ck = (TCGAKOT15CommitmentKey) commitmentKey;
        TCGAKOT15Commitment com = (TCGAKOT15Commitment) commitment;
        TCAKOT15OpenValue open = (TCAKOT15OpenValue) openValue;

        for (int i = 0; i < messageBlock.length(); i++) {

            if( !posInstance.verify(new MessageBlock(messageBlock.get(i)), open.getSpsPosSignatures()[i], open.spsPosVerificationKey, oneTimePublicKeys[i])) {
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
    public MessageBlock mapToPlainText(byte[] bytes) {
        // returns (P^m, P, ..., P) where m = Z_p.injectiveValueOf(bytes).

        GroupElementPlainText[] msgBlock = new GroupElementPlainText[pp.getMessageLength()];
        msgBlock[0] = new GroupElementPlainText(
                getG2GroupGenerator().pow(pp.getZp().injectiveValueOf(bytes))
        );
        for (int i = 1; i < pp.getMessageLength(); i++) {
            msgBlock[i] = new GroupElementPlainText(getG2GroupGenerator());
        }

        return new MessageBlock(msgBlock);
    }

    @Override
    public Commitment restoreCommitment(Representation repr) {
        return new TCAKOT15Commitment(getG2GroupGenerator().getStructure(), repr);
    }

    @Override
    public OpenValue restoreOpenValue(Representation repr) {
        return new TCAKOT15OpenValue(
                getG1GroupGenerator().getStructure(),
                getG2GroupGenerator().getStructure(),
                repr);
    }

    @Override
    public Representation getRepresentation() {
        return new ReprUtil(this).serialize();
    }
}
