package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link CipherText} for the {@link ABECPWat11Small}.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens, Raphael Heitjohann
 */
public class ABECPWat11SmallCipherText implements CipherText {

    @Represented
    private Policy policy;

    @Represented(restorer = "GT")
    private GroupElement c; // in G_T

    @Represented(restorer = "G1")
    private GroupElement cPrime; // in G_1

    @Represented(restorer = "foo -> G1")
    private Map<BigInteger, GroupElement> mapC; // in G_1

    @Represented(restorer = "foo -> G1")
    private Map<BigInteger, GroupElement> mapD; // in G_1

    public ABECPWat11SmallCipherText(Policy policy, GroupElement c, GroupElement cPrime,
                                     Map<BigInteger, GroupElement> mapC,
                                     Map<BigInteger, GroupElement> mapD) {
        this.policy = policy;
        this.c = c;
        this.cPrime = cPrime;
        this.mapC = mapC;
        this.mapD = mapD;
    }

    public ABECPWat11SmallCipherText(Representation repr, ABECPWat11SmallPublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").register(pp.getGroupGT(), "GT")
                .deserialize(repr);
    }

    public Policy getPolicy() {
        return policy;
    }

    public GroupElement getC() {
        return c;
    }

    public GroupElement getcPrime() {
        return cPrime;
    }

    public Map<BigInteger, GroupElement> getMapC() {
        return mapC;
    }

    public Map<BigInteger, GroupElement> getMapD() {
        return mapD;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mapC == null) ? 0 : mapC.hashCode());
        result = prime * result + ((mapD == null) ? 0 : mapD.hashCode());
        result = prime * result + ((c == null) ? 0 : c.hashCode());
        result = prime * result + ((cPrime == null) ? 0 : cPrime.hashCode());
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
        ABECPWat11SmallCipherText other = (ABECPWat11SmallCipherText) obj;
        return Objects.equals(mapC, other.mapC)
                && Objects.equals(mapD, other.mapD)
                && Objects.equals(c, other.c)
                && Objects.equals(cPrime, other.cPrime)
                && Objects.equals(policy, other.policy);
    }
}
