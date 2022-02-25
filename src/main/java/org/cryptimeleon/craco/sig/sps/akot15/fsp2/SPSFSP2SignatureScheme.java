package org.cryptimeleon.craco.sig.sps.akot15.fsp2;

import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;
import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.craco.sig.*;
import org.cryptimeleon.craco.sig.sps.akot15.AKOT15SharedPublicParameters;
import org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15Commitment;
import org.cryptimeleon.craco.sig.sps.akot15.tc.TCAKOT15CommitmentScheme;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15Commitment;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15CommitmentKey;
import org.cryptimeleon.craco.sig.sps.akot15.tcgamma.TCGAKOT15XSIGCommitment;
import org.cryptimeleon.craco.sig.sps.akot15.xsig.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;

import java.util.Objects;

public class SPSFSP2SignatureScheme implements MultiMessageStructurePreservingSignatureScheme {

    @Represented
    AKOT15SharedPublicParameters pp;

    @Represented
    SPSXSIGSignatureScheme xsigInstance;

    @Represented
    TCAKOT15CommitmentScheme tcInstance;


    public SPSFSP2SignatureScheme(AKOT15SharedPublicParameters pp) {
        this.pp = pp;

        //instantiate nested building blocks
        SPSXSIGPublicParameters pp_xsig = new SPSXSIGPublicParameters(pp);

        xsigInstance = new SPSXSIGSignatureScheme(pp_xsig);

        tcInstance = new TCAKOT15CommitmentScheme(pp_xsig);
    }

    @Override
    public SignatureKeyPair<SPSFSP2VerificationKey, SPSXSIGSigningKey> generateKeyPair(int numberOfMessages) {

        // generate keys via building blocks
        SignatureKeyPair<SPSXSIGVerificationKey, SPSXSIGSigningKey> key_xsig = xsigInstance.generateKeyPair(numberOfMessages);
        TCGAKOT15CommitmentKey key_tc = tcInstance.generateKey();

        return new SignatureKeyPair<>(new SPSFSP2VerificationKey(key_xsig.getVerificationKey(), key_tc), key_xsig.getSigningKey());
    }

    @Override
    public Signature sign(PlainText plainText, SigningKey secretKey) {

        if(!(secretKey instanceof SPSXSIGSigningKey)) {
            throw new IllegalArgumentException("this is not a valid signing key for this scheme");
        }

        if((plainText instanceof GroupElementPlainText)) {
            plainText = new MessageBlock(plainText);
        }

        if(!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("this is not a valid message for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        SPSXSIGSigningKey sk = (SPSXSIGSigningKey) secretKey;

        CommitmentPair tcCommitmentPair = tcInstance.commit(messageBlock);

        // as defined by the public parameters, TCG returns a special variant of the commitment that includes the
        //      2 additional values needed by XSIG
        TCGAKOT15XSIGCommitment com = ((TCGAKOT15XSIGCommitment)tcCommitmentPair.getCommitment());

        SPSXSIGSignature sigma = (SPSXSIGSignature) xsigInstance.sign(sk, com.toMessageBlock());

        return new SPSFSP2Signature(sigma, tcCommitmentPair);
    }

    @Override
    public Boolean verify(PlainText plainText, Signature signature, VerificationKey publicKey) {

        if((plainText instanceof GroupElementPlainText)) {
            plainText = new MessageBlock(plainText);
        }

        if(!(plainText instanceof MessageBlock)) {
            throw new IllegalArgumentException("this is not a valid message for this scheme");
        }

        if(!(publicKey instanceof SPSFSP2VerificationKey)) {
            throw new IllegalArgumentException("this is not a valid verification key for this scheme");
        }

        if(!(signature instanceof SPSFSP2Signature)) {
            throw new IllegalArgumentException("this is not a valid signature for this scheme");
        }

        MessageBlock messageBlock = (MessageBlock) plainText;
        SPSFSP2VerificationKey vk = (SPSFSP2VerificationKey) publicKey;
        SPSFSP2Signature sigma = (SPSFSP2Signature) signature;

        CommitmentPair commitmentPair = sigma.getCommitmentPair_tc();

        return xsigInstance.verify(((TCGAKOT15XSIGCommitment)commitmentPair.getCommitment()).toMessageBlock(), sigma.getSigma_xsig(), vk.getVk_xsig())
            && tcInstance.verify(sigma.getCommitmentPair_tc().getCommitment(), sigma.getCommitmentPair_tc().getOpenValue(), messageBlock);
    }


    @Override
    public PlainText restorePlainText(Representation repr) {
        // The message space for this scheme is a simple vector of GroupElements in G2
        return new MessageBlock(repr, r -> new GroupElementPlainText(r, pp.getG2GroupGenerator().getStructure()));
    }

    @Override
    public Signature restoreSignature(Representation repr) {
        return new SPSFSP2Signature(
                pp.getG1GroupGenerator().getStructure(),
                pp.getG2GroupGenerator().getStructure(),
                repr);
    }

    @Override
    public SigningKey restoreSigningKey(Representation repr) {
        return new SPSXSIGSigningKey(
                pp.getG1GroupGenerator().getStructure(),
                pp.getG2GroupGenerator().getStructure(),
                repr);
    }

    @Override
    public VerificationKey restoreVerificationKey(Representation repr) {
        return new SPSFSP2VerificationKey(
                pp.getG1GroupGenerator().getStructure(),
                pp.getG2GroupGenerator().getStructure(),
                repr);
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
        return new ReprUtil(this).serialize();
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSFSP2SignatureScheme that = (SPSFSP2SignatureScheme) o;
        return Objects.equals(pp, that.pp) && Objects.equals(xsigInstance, that.xsigInstance) && Objects.equals(tcInstance, that.tcInstance);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pp, xsigInstance, tcInstance);
    }

}
