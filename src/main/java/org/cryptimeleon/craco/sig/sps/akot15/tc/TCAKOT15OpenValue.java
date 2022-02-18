package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.craco.sig.sps.akot15.pos.SPSPOSSignature;
import org.cryptimeleon.craco.sig.sps.akot15.pos.SPSPOSVerificationKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

/**
 * An opening to a commitment used by the TCAKOT15 implementation.
 * */
public class TCAKOT15OpenValue implements OpenValue {

    // Opening as defined in TC Gamma
    @Represented(restorer = "G1")
    protected GroupElement group1ElementGamma;

    /**
     *
     * */
    @Represented
    protected SPSPOSVerificationKey spsPosVerificationKey;

    @Represented(restorer = "G2")
    protected GroupElement[] spsPosOTVerificationKeys;

    /**
     * sigma_{pos} in the paper.
     */
    @Represented
    protected SPSPOSSignature[] spsPosSignatures;


    public TCAKOT15OpenValue(GroupElement group1ElementGamma, SPSPOSVerificationKey verificationKey, GroupElement[] oneTimeVerificationKeys, SPSPOSSignature[] signatures) {
        this.group1ElementGamma = group1ElementGamma;
        this.spsPosVerificationKey = verificationKey;
        this.spsPosOTVerificationKeys = oneTimeVerificationKeys;
        this.spsPosSignatures = signatures;
    }

    public TCAKOT15OpenValue(Group g1, Group g2, Representation repr) {
        new ReprUtil(this).register(g1, "G1").register(g2, "G2").deserialize(repr);
    }




    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        return null;
    }

    public SPSPOSVerificationKey getSpsPosVerificationKey() {
        return spsPosVerificationKey;
    }

    public void setSpsPosVerificationKey(SPSPOSVerificationKey spsPosVerificationKey) {
        this.spsPosVerificationKey = spsPosVerificationKey;
    }

    public GroupElement[] getSpsPosOTVerificationKeys() {
        return spsPosOTVerificationKeys;
    }

    public void setSpsPosOTVerificationKeys(GroupElement[] spsPosOTVerificationKeys) {
        this.spsPosOTVerificationKeys = spsPosOTVerificationKeys;
    }

    public SPSPOSSignature[] getSpsPosSignatures() {
        return spsPosSignatures;
    }

    public void setSpsPosSignatures(SPSPOSSignature[] spsPosSignatures) {
        this.spsPosSignatures = spsPosSignatures;
    }

    public GroupElement getGroup1ElementGamma() {
        return group1ElementGamma;
    }
}
