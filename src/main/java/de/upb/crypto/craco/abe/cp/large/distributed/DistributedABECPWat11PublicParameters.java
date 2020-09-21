package de.upb.crypto.craco.abe.cp.large.distributed;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11PublicParameters;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

public class DistributedABECPWat11PublicParameters extends ABECPWat11PublicParameters implements PublicParameters {

    @Represented(restorer = "foo -> bilinearGroup::getG1")
    private Map<BigInteger, GroupElement> t;

    @Represented(restorer = "foo -> bilinearGroup::getGT")
    private Map<Integer, GroupElement> verificationKeys;

    @Represented
    private Integer threshold;

    public DistributedABECPWat11PublicParameters() {
    }

    public DistributedABECPWat11PublicParameters(Representation repr) {
        super(repr);
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Map<BigInteger, GroupElement> getT() {
        return t;
    }

    public void setT(Map<BigInteger, GroupElement> t) {
        this.t = t;
    }

    public Map<Integer, GroupElement> getVerificationKeys() {
        return verificationKeys;
    }

    public void setVerificationKeys(Map<Integer, GroupElement> verificationKeys) {
        this.verificationKeys = verificationKeys;
    }

    public int getThreshold() {
        return threshold;
    }

    public void setThreshold(int threshold) {
        this.threshold = threshold;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((t == null) ? 0 : t.hashCode());
        result = prime * result + threshold;
        result = prime * result + ((verificationKeys == null) ? 0 : verificationKeys.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        DistributedABECPWat11PublicParameters other = (DistributedABECPWat11PublicParameters) obj;
        return Objects.equals(t, other.t)
                && Objects.equals(threshold, other.threshold)
                && Objects.equals(verificationKeys, other.verificationKeys);
    }

}