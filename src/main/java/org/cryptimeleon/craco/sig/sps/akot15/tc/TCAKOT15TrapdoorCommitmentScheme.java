package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.Commitment;
import org.cryptimeleon.craco.commitment.CommitmentPair;
import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

public class TCAKOT15TrapdoorCommitmentScheme implements CommitmentScheme {

    @Represented
    private BilinearGroup bGroup;

    @Represented(restorer = "bGroup")
    private GroupElement group1ElementG;

    @Represented(restorer = "bGroup")
    private GroupElement group2ElementH;


    public TCAKOT15TrapdoorCommitmentScheme(BilinearGroup bGroup) {
        this.bGroup = bGroup;
        this.group1ElementG = bGroup.getG1().getUniformlyRandomNonNeutral();
        this.group2ElementH = bGroup.getG2().getUniformlyRandomNonNeutral();
    }

    public TCAKOT15TrapdoorCommitmentScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }


    @Override
    public CommitmentPair commit(PlainText plainText) {



        return null;
    }

    @Override
    public boolean verify(Commitment commitment, OpenValue openValue, PlainText plainText) {
        return false;
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
    public Representation getRepresentation() {
        return null;
    }

}
