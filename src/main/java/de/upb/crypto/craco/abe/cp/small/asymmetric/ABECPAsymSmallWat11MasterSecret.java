package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.abe.cp.small.ABECPWat11SmallMasterSecret;
import de.upb.crypto.craco.interfaces.pe.MasterSecret;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

public class ABECPAsymSmallWat11MasterSecret implements MasterSecret {

    @Represented(restorer = "G1")
    private GroupElement gAlpha; // in G_1

    public ABECPAsymSmallWat11MasterSecret(GroupElement gAlpha) {
        this.gAlpha = gAlpha;
    }

    public ABECPAsymSmallWat11MasterSecret(Representation repr, Group groupG1) {
        new ReprUtil(this).register(groupG1, "G1").deserialize(repr);
    }

    public GroupElement get() {
        return gAlpha;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }


    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((gAlpha == null) ? 0 : gAlpha.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABECPAsymSmallWat11MasterSecret other = (ABECPAsymSmallWat11MasterSecret) obj;
        if (gAlpha == null) {
            return other.gAlpha == null;
        } else return gAlpha.equals(other.gAlpha);
    }
}
