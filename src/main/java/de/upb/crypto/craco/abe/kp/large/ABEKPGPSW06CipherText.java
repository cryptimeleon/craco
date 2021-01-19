package de.upb.crypto.craco.abe.kp.large;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.kem.abe.kp.large.ABEKPGPSW06KEMCipherText;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Map;
import java.util.Objects;

/**
 * A {@link CipherText} for the {@link ABEKPGPSW06}.
 *
 *
 */
public class ABEKPGPSW06CipherText extends ABEKPGPSW06KEMCipherText {
    /**
     * E' := m * Y^s \in G_T
     */
    @Represented(restorer = "GT")
    private GroupElement ePrime;

    public ABEKPGPSW06CipherText(GroupElement ePrime, GroupElement eTwoPrime, Map<Attribute, GroupElement> eElementMap,
                                 SetOfAttributes attributes) {
        super(attributes, eTwoPrime, eElementMap);
        this.ePrime = ePrime;
    }

    public ABEKPGPSW06CipherText(Representation repr, ABEKPGPSW06PublicParameters kpp) {
        new ReprUtil(this).register(kpp.getGroupG1(), "G1").register(kpp.getGroupGT(), "GT")
                .deserialize(repr);
    }

    public GroupElement getEPrime() {
        return ePrime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        ABEKPGPSW06CipherText other = (ABEKPGPSW06CipherText) o;
        return super.equals(other) && Objects.equals(ePrime, other.ePrime);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((ePrime == null) ? 0 : ePrime.hashCode());
        return result;
    }
}
