package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.*;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.sps.akot15.pos.*;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

public class TCAKOT15CommitmentScheme implements CommitmentScheme {

    @Represented
    TCAKOT15PublicParameters pp;

    SPSPOSSignatureScheme posInstance;
    TCGAKOT15CommitmentScheme gbcInstance;

    TCGAKOT15CommitmentKey commitmentKey;

    ZpElement[] oneTimeSecretKeys;
    GroupElement[] oneTimePublicKeys;

    MessageBlock commitMsg;

    public TCAKOT15CommitmentScheme(TCAKOT15PublicParameters pp) {
        super();
        this.pp = pp;

        //set G,H
        SPSPOSPublicParameters posPP = new SPSPOSPublicParameters(pp.bilinearGroup, 1);
        posPP.setGH(pp.group1ElementG, pp.group2ElementH);

        TCGAKOT15PublicParameters gbcPP = new TCGAKOT15PublicParameters(pp.bilinearGroup, pp.getMessageLength() + 2);
        gbcPP.setGH(pp.group1ElementG, pp.group2ElementH);

        //create nested signature scheme instance
        this.posInstance = new SPSPOSSignatureScheme(posPP);
        this.gbcInstance = new TCGAKOT15CommitmentScheme(gbcPP);

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

        System.out.println(posInstance.pp.getG1GroupGenerator().equals(gbcInstance.pp.getG1GroupGenerator()));
        System.out.println("-------");

        for (int i = 0; i < msg_com.length; i++) {

            GroupElement msg_test1 = pp.getG1GroupGenerator().pow(((RingElementPlainText)commitMsg.get(i)).getRingElement()).compute();
            GroupElement msg_text2 = msg_com[i].get().compute();

            System.out.println(msg_test1.equals(msg_text2));
        }

        return gbcInstance.verify(com, new TCGAKOT15OpenValue(open.getGroup1ElementGamma()), new MessageBlock(msg_com));
    }


    @Override
    public MessageBlock mapToPlainText(byte[] bytes) {
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
    public Commitment restoreCommitment(Representation repr) {
        return new TCAKOT15Commitment(pp.getG2GroupGenerator().getStructure(), repr);
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
        return new ReprUtil(this).serialize();
    }
}
