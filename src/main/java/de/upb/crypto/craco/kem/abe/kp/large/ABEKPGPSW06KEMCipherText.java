package de.upb.crypto.craco.kem.abe.kp.large;

import de.upb.crypto.craco.abe.kp.large.ABEKPGPSW06PublicParameters;
import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

import java.util.Map;

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

        if (attributes != null ? !attributes.equals(that.attributes) : that.attributes != null)
            return false;
        if (eTwoPrime != null ? !eTwoPrime.equals(that.eTwoPrime) : that.eTwoPrime != null)
            return false;
        return eElementMap != null ? eElementMap.equals(that.eElementMap) : that.eElementMap == null;
    }

    @Override
    public int hashCode() {
        int result = attributes != null ? attributes.hashCode() : 0;
        result = 31 * result + (eTwoPrime != null ? eTwoPrime.hashCode() : 0);
        result = 31 * result + (eElementMap != null ? eElementMap.hashCode() : 0);
        return result;
    }
}
