package de.upb.crypto.craco.abe.cp.large.distributed;

import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.abe.distributed.KeyShare;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

import java.util.Map;

public class DistributedABECPWat11KeyShare implements KeyShare {

    @Represented(restorer = "G1")
    private GroupElement d_prime;

    @Represented(restorer = "G1")
    private GroupElement d_two_prime;

    @Represented
    private Integer serverID;

    @Represented(restorer = "foo -> G1")
    private Map<Attribute, GroupElement> d_xi;

    @Represented
    private SetOfAttributes omega;

    @SuppressWarnings("unused")
    private Group groupG1;

    public DistributedABECPWat11KeyShare(GroupElement d_prime, GroupElement d_two_prime, int serverID,
                                         Map<Attribute, GroupElement> d_xi, SetOfAttributes omega) {
        this.d_prime = d_prime;
        this.d_two_prime = d_two_prime;
        this.serverID = serverID;
        this.d_xi = d_xi;
        this.omega = omega;
    }

    public DistributedABECPWat11KeyShare(Representation repr, DistributedABECPWat11PublicParameters pp) {
        groupG1 = pp.getGroupG1();
        new ReprUtil(this).register(pp.groupG1, "G1").deserialize(repr);
    }

    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getD_prime() {
        return d_prime;
    }

    public GroupElement getD_two_prime() {
        return d_two_prime;
    }

    @Override
    public int getServerID() {
        return serverID;
    }

    public Map<Attribute, GroupElement> getD_xi() {
        return d_xi;
    }

    @Override
    public SetOfAttributes getKeyIndex() {
        return omega;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((d_prime == null) ? 0 : d_prime.hashCode());
        result = prime * result + ((d_two_prime == null) ? 0 : d_two_prime.hashCode());
        result = prime * result + ((d_xi == null) ? 0 : d_xi.hashCode());
        result = prime * result + ((omega == null) ? 0 : omega.hashCode());
        result = prime * result + serverID;
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
        DistributedABECPWat11KeyShare other = (DistributedABECPWat11KeyShare) obj;
        if (d_prime == null) {
            if (other.d_prime != null)
                return false;
        } else if (!d_prime.equals(other.d_prime))
            return false;
        if (d_two_prime == null) {
            if (other.d_two_prime != null)
                return false;
        } else if (!d_two_prime.equals(other.d_two_prime))
            return false;
        if (d_xi == null) {
            if (other.d_xi != null)
                return false;
        } else if (!d_xi.equals(other.d_xi))
            return false;
        if (omega == null) {
            if (other.omega != null)
                return false;
        } else if (!omega.equals(other.omega))
            return false;
        if (serverID != other.serverID)
            return false;
        return true;
    }
}
