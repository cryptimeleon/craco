package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

import java.math.BigInteger;
import java.util.Map;

/**
 * A {@link CipherText} for the {@link ABECPWat11Small}.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens
 */
public class ABECPWat11SmallCipherText implements CipherText {

    @Represented
    private Policy policy;

    @Represented(structure = "groupGT", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement e_prime; // in G_T

    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement e_two_prime; // in G_1

    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "groupG1", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    private Map<BigInteger, GroupElement> e1; // in G_1

    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "groupG1", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    private Map<BigInteger, GroupElement> e2; // in G_1

    @SuppressWarnings("unused")
    private Group groupG1;

    @SuppressWarnings("unused")
    private Group groupGT;

    public ABECPWat11SmallCipherText(Policy policy, GroupElement e_prime, GroupElement e_two_prime,
                                     Map<BigInteger, GroupElement> e1,
                                     Map<BigInteger, GroupElement> e2) {
        this.policy = policy;
        this.e_prime = e_prime;
        this.e_two_prime = e_two_prime;
        this.e1 = e1;
        this.e2 = e2;
    }

    public ABECPWat11SmallCipherText(Representation repr, ABECPWat11SmallPublicParameters pp) {
        groupG1 = pp.getGroupG1();
        groupGT = pp.getGroupGT();
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    public Policy getPolicy() {
        return policy;
    }

    public GroupElement getE_prime() {
        return e_prime;
    }

    public GroupElement getE_two_prime() {
        return e_two_prime;
    }

    public Map<BigInteger, GroupElement> getE1() {
        return e1;
    }

    public Map<BigInteger, GroupElement> getE2() {
        return e2;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((e1 == null) ? 0 : e1.hashCode());
        result = prime * result + ((e2 == null) ? 0 : e2.hashCode());
        result = prime * result + ((e_prime == null) ? 0 : e_prime.hashCode());
        result = prime * result + ((e_two_prime == null) ? 0 : e_two_prime.hashCode());
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
        if (e1 == null) {
            if (other.e1 != null)
                return false;
        } else if (!e1.equals(other.e1))
            return false;
        if (e2 == null) {
            if (other.e2 != null)
                return false;
        } else if (!e2.equals(other.e2))
            return false;
        if (e_prime == null) {
            if (other.e_prime != null)
                return false;
        } else if (!e_prime.equals(other.e_prime))
            return false;
        if (e_two_prime == null) {
            if (other.e_two_prime != null)
                return false;
        } else if (!e_two_prime.equals(other.e_two_prime))
            return false;
        if (policy == null) {
            if (other.policy != null)
                return false;
        } else if (!policy.equals(other.policy))
            return false;
        return true;
    }
}
