package de.upb.crypto.craco.kem.abe.kp.large;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06PublicParameters;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Map;
import java.util.Objects;

public class ABEKPGPSW06KEMCipherText implements CipherText {
    /**
     * ciphertext's attributes \omega
     */
    @Represented
    protected SetOfAttributes attributes;

    /**
     * E'' := g^s \in G_1
     */
    @Represented(restorer = "G1")
    protected GroupElement eTwoPrime;

    /**
     * E_i := T_i^s , i \in attributes, T_i \in G1
     */
    @Represented(restorer = "attr -> G1")
    protected Map<Attribute, GroupElement> eElementMap;

    public ABEKPGPSW06KEMCipherText(SetOfAttributes attributes, GroupElement eTwoPrime,
                                    Map<Attribute, GroupElement> eElementMap) {
        this.attributes = attributes;
        this.eTwoPrime = eTwoPrime;
        this.eElementMap = eElementMap;
    }

    public ABEKPGPSW06KEMCipherText(Representation repr, ABEKPGPSW06PublicParameters kpp) {
        new ReprUtil(this).register(kpp.getGroupG1(), "G1").deserialize(repr);
    }

    public ABEKPGPSW06KEMCipherText() {

    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Map<Attribute, GroupElement> getEElementMap() {
        return eElementMap;
    }

    public SetOfAttributes getAttributes() {
        return attributes;
    }

    public GroupElement getETwoPrime() {
        return eTwoPrime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        ABEKPGPSW06KEMCipherText that = (ABEKPGPSW06KEMCipherText) o;

        return Objects.equals(attributes, that.attributes)
                && Objects.equals(eTwoPrime, that.eTwoPrime)
                && Objects.equals(eElementMap, that.eElementMap);
    }

    @Override
    public int hashCode() {
        int result = attributes != null ? attributes.hashCode() : 0;
        result = 31 * result + (eTwoPrime != null ? eTwoPrime.hashCode() : 0);
        result = 31 * result + (eElementMap != null ? eElementMap.hashCode() : 0);
        return result;
    }
}
