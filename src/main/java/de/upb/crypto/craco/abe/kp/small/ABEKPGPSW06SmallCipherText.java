package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.MapRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.HashMap;
import java.util.Map;

/**
 * A {@link CipherText} for the {@link ABEKPGPSW06Small}.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens
 */
public class ABEKPGPSW06SmallCipherText implements CipherText {

    //E_prime := m * Y^s \in G_T
    private GroupElement E_prime;
    //E_i := T_i^s , i \in attributes, T_i \in G1
    private Map<Attribute, GroupElement> E;

    public ABEKPGPSW06SmallCipherText(GroupElement E_prime, Map<Attribute, GroupElement> E) {
        this.E_prime = E_prime;
        this.E = E;
    }

    public ABEKPGPSW06SmallCipherText(Representation representation, ABEKPGPSW06SmallPublicParameters kpp) {
        E = new HashMap<Attribute, GroupElement>();
        representation.obj().get("E").map().forEach(entry -> E
                .put((Attribute) entry.getKey().repr().recreateRepresentable(), kpp.getGroupG1()
                        .getElement(entry.getValue())));
        E_prime = kpp.getGroupGT().getElement(representation.obj().get("E_prime"));
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        MapRepresentation map = new MapRepresentation();
        E.forEach((a, g) -> map.put(new RepresentableRepresentation(a), g.getRepresentation()));
        repr.put("E", map);
        repr.put("E_prime", E_prime.getRepresentation());
        return repr;
    }

    public GroupElement getE_prime() {
        return E_prime;
    }

    public Map<Attribute, GroupElement> getE() {
        return E;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((E == null) ? 0 : E.hashCode());
        result = prime * result + ((E_prime == null) ? 0 : E_prime.hashCode());
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
        ABEKPGPSW06SmallCipherText other = (ABEKPGPSW06SmallCipherText) obj;
        if (E == null) {
            if (other.E != null)
                return false;
        } else if (!E.equals(other.E))
            return false;
        if (E_prime == null) {
            if (other.E_prime != null)
                return false;
        } else if (!E_prime.equals(other.E_prime))
            return false;
        return true;
    }

}
