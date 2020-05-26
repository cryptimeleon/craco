package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Map;

public class ABECPWat11AsymSmallCipherText implements CipherText {

    @Represented
    private Policy policy;

    @Represented(restorer = "GT")
    private GroupElement c; // C in G_T

    @Represented(restorer = "G2")
    private GroupElement cPrime; // C' in G_2

    @Represented(restorer = "foo -> G1")
    private Map<BigInteger, GroupElement> mapC; // C_1 to C_\ell in G_1

    @Represented(restorer = "foo -> G2")
    private Map<BigInteger, GroupElement> mapD; // D_1 to D_\ell in G_2

    public ABECPWat11AsymSmallCipherText(Policy policy, GroupElement c, GroupElement cPrime,
                                         Map<BigInteger, GroupElement> mapC, Map<BigInteger, GroupElement> mapD) {
        this.policy = policy;
        this.c = c;
        this.cPrime = cPrime;
        this.mapC = mapC;
        this.mapD = mapD;
    }

    public ABECPWat11AsymSmallCipherText(Representation repr, ABECPWat11AsymSmallPublicParameters pp) {
        new ReprUtil(this).register(pp.getE()).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Policy getPolicy() {
        return policy;
    }

    public GroupElement getC() {
        return c;
    }

    public GroupElement getCPrime() {
        return cPrime;
    }

    public Map<BigInteger, GroupElement> getMapC() {
        return mapC;
    }

    public Map<BigInteger, GroupElement> getMapD() {
        return mapD;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((c == null) ? 0 : c.hashCode());
        result = prime * result + ((cPrime == null) ? 0 : cPrime.hashCode());
        result = prime * result + ((mapC == null) ? 0 : mapC.hashCode());
        result = prime * result + ((mapD == null) ? 0 : mapD.hashCode());
        result = prime * result + ((policy == null) ? 0 : policy.hashCode());
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
        ABECPWat11AsymSmallCipherText other = (ABECPWat11AsymSmallCipherText) obj;
        if (c == null) {
            if (other.c != null)
                return false;
        } else if (!c.equals(other.c))
            return false;
        if (cPrime == null) {
            if (other.cPrime != null)
                return false;
        } else if (!cPrime.equals(other.cPrime))
            return false;
        if (mapC == null) {
            if (other.mapC != null)
                return false;
        } else if (!mapC.equals(other.mapC))
            return false;
        if (mapD == null) {
            if (other.mapD != null)
                return false;
        } else if (!mapD.equals(other.mapD))
            return false;
        if (policy == null) {
            return other.policy == null;
        } else return policy.equals(other.policy);
    }
}