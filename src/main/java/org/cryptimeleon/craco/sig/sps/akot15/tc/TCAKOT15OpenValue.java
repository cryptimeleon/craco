package org.cryptimeleon.craco.sig.sps.akot15.tc;

import org.cryptimeleon.craco.commitment.OpenValue;
import org.cryptimeleon.craco.sig.sps.akot15.pos.SPSPOSSignature;
import org.cryptimeleon.craco.sig.sps.akot15.pos.SPSPOSVerificationKey;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.annotations.AnnotatedUbrUtil;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;

import java.util.Arrays;
import java.util.Objects;
import java.util.stream.IntStream;

/**
 * An opening to a commitment used by the TCAKOT15 implementation.
 * */
public class TCAKOT15OpenValue implements OpenValue {

    /**
     * Opening as defined in TC Gamma
     */
    @Represented(restorer = "G1")
    protected GroupElement group1ElementGamma;

    /**
     *
     */
    @Represented
    protected SPSPOSVerificationKey spsPosVerificationKey;

    /**
     *
     */
    @Represented(restorer = "[G1]")
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
        ObjectRepresentation objRepr = (ObjectRepresentation) repr;

        this.group1ElementGamma = g1.restoreElement(objRepr.get("tcgOpen"));
        this.spsPosVerificationKey = new SPSPOSVerificationKey(objRepr.get("posVk"), g1);
        this.spsPosOTVerificationKeys = g1.restoreVector(objRepr.get("posOtVk")).stream().toArray(GroupElement[]::new);

        this.spsPosSignatures = objRepr.get("posSigmas").list().stream().map(
                x -> new SPSPOSSignature(x, g2)
        ).toArray(SPSPOSSignature[]::new);
    }


    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation objRepr = new ObjectRepresentation();

        objRepr.put("tcgOpen", group1ElementGamma.getRepresentation());
        objRepr.put("posVk", spsPosVerificationKey.getRepresentation());

        objRepr.put("posOtVk", new ListRepresentation(
                Arrays.stream(spsPosOTVerificationKeys).sequential().map(x -> x.getRepresentation()).toArray(Representation[]::new)
        ));

        objRepr.put("posSigmas", new ListRepresentation(
                Arrays.stream(spsPosSignatures).sequential().map(x -> x.getRepresentation()).toArray(Representation[]::new)
        ));

        return objRepr;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TCAKOT15OpenValue)) return false;
        TCAKOT15OpenValue that = (TCAKOT15OpenValue) o;
        return Objects.equals(group1ElementGamma, that.group1ElementGamma)
                && Objects.equals(spsPosVerificationKey, that.spsPosVerificationKey)
                && Arrays.equals(spsPosOTVerificationKeys, that.spsPosOTVerificationKeys)
                && Arrays.equals(spsPosSignatures, that.spsPosSignatures);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(group1ElementGamma, spsPosVerificationKey);
        result = 31 * result + Arrays.hashCode(spsPosOTVerificationKeys);
        result = 31 * result + Arrays.hashCode(spsPosSignatures);
        return result;
    }

}
