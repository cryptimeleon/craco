package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.craco.commitment.trapdoorcommitment.*;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.sps.akot15.pos.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.IntStream;

public class TCAKOT15TrapdoorCommitmentScheme implements TrapdoorCommitmentScheme {

    @Represented
    TCAKOT15PublicParameters pp;

    SPSPOSSignatureScheme[] posInstances;


    public TCAKOT15TrapdoorCommitmentScheme(TCAKOT15PublicParameters pp) {
        super();
        this.pp = pp;

        //create nested signature scheme instances
        //TODO do we really need k-instances?

        this.posInstances = new SPSPOSSignatureScheme[pp.getMessageLength()];
        for (int i = 0; i < pp.getMessageLength(); i++) {
            SPSPOSPublicParameters posPP = new SPSPOSPublicParameters(pp.bilinearGroup, 1);
            posPP.setGroup1GeneratorG(pp.getG1GroupGenerator());
            posPP.setGroup2GeneratorH(pp.getG2GroupGenerator());
            this.posInstances[i] = new SPSPOSSignatureScheme(posPP);
        }
    }


    @Override
    public TrapdoorCommitmentKeyPair<TCAKOT15CommitmentKey, TCAKOT15TrapdoorKey> generateKeyPair() {

        // Note that the function inlines the key generation used by the
        // gamma binding TC scheme this scheme builds upon.

        ZpElement[] exponentsRho = IntStream.range(0, pp.getMessageLength()).mapToObj(
                x-> pp.getZp().getUniformlyRandomNonzeroElement()
        ).toArray(ZpElement[]::new);

        GroupElement[] group2ElementsX = Arrays.stream(exponentsRho).map(
                x-> pp.getG2GroupGenerator().pow(x).compute()
        ).toArray(GroupElement[]::new);

        TCAKOT15CommitmentKey tcGammaCommitmentKey = new TCAKOT15CommitmentKey(group2ElementsX);

        TCAKOT15TrapdoorKey tcGammaTrapdoorKey = new TCAKOT15TrapdoorKey(exponentsRho);

        return new TrapdoorCommitmentKeyPair<>(tcGammaCommitmentKey, tcGammaTrapdoorKey);
    }

    @Override
    public CommitmentPair commit(PlainText plainText, CommitmentKey commitmentKey) {

        if(!(commitmentKey instanceof TCAKOT15CommitmentKey)) {
            throw new IllegalArgumentException("This is not a valid commitment key for this scheme");
        }

        if(!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("This is not a valid message for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        TCAKOT15CommitmentKey ck = (TCAKOT15CommitmentKey) commitmentKey;

        // vk_pos, sk_pos
        // note that ovk_pos and osk_pos are created as a side effect on key generation

        SignatureKeyPair<SPSPOSVerificationKey, SPSPOSSigningKey> posKeyPair = posInstances[0].generateKeyPair(1);

        SPSPOSSignature[] sigmas = new SPSPOSSignature[pp.getMessageLength()];

        ZpElement[] oneTimeKeys = new ZpElement[pp.getMessageLength()];

        // create sequential signature

        for (int i = 0; i < sigmas.length; i++) {
            sigmas[i] = posInstances[i].sign(messageBlock.get(i), posKeyPair.getSigningKey());
            oneTimeKeys[i] = posKeyPair.getSigningKey().getOneTimeKey();    // TODO rethink pos one time key access
            posInstances[i].updateOneTimeKey(posKeyPair);
        }

        ArrayList<ZpElement> msg_sk = new ArrayList<>();

        msg_sk.add(posKeyPair.getSigningKey().getExponentW());
        msg_sk.addAll(Arrays.asList(posKeyPair.getSigningKey().getExponentsChi()));
        msg_sk.addAll(Arrays.asList(oneTimeKeys));

        MessageBlock msgBlock_sk = new MessageBlock(
                msg_sk.stream().map(RingElementPlainText::new).toArray(RingElementPlainText[]::new)
        );

        CommitmentPair com = tcGammaCommit(msgBlock_sk, ck);

        return new CommitmentPair(com.getCommitment(), new TCAKOT15OpenValue());
    }

    private CommitmentPair tcGammaCommit(MessageBlock plainText, TCAKOT15CommitmentKey ck) {
        return null; //TODO
    }

    @Override
    public boolean verify(PlainText plainText, CommitmentKey commitmentKey, Commitment commitment, OpenValue openValue) {
        return false;
    }

    @Override
    public TrapdoorCommitmentPair trapdoorCommit() {
        return null;
    }

    @Override
    public OpenValue trapdoorOpen(PlainText plainText, EquivocationKey equivocationKey, TrapdoorKey trapdoorKey) {
        return null;
    }





    @Override
    public PlainText mapToPlainText(byte[] bytes) {
        return null;
    }

    @Override
    public Commitment restoreCommitment(Representation repr) {
        return null;
    }

    @Override
    public OpenValue restoreOpenValue(Representation repr) {
        return null;
    }

    @Override
    public EquivocationKey restoreTrapdoorValue(Representation repr) {
        return null;
    }

    @Override
    public Representation getRepresentation() {
        return null;
    }
}
