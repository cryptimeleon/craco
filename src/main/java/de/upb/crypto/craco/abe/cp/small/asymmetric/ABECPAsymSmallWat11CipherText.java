package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Map;

public class ABECPAsymSmallWat11CipherText implements CipherText {

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

    public ABECPAsymSmallWat11CipherText(Policy policy, GroupElement c, GroupElement cPrime,
                                         Map<BigInteger, GroupElement> mapC, Map<BigInteger, GroupElement> mapD) {
        this.policy = policy;
        this.c = c;
        this.cPrime = cPrime;
        this.mapC = mapC;
        this.mapD = mapD;
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
}
