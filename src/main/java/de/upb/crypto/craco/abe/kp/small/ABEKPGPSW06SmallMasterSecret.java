package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.math.serialization.MapRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.HashMap;
import java.util.Map;

/**
 * The master secret for the {@link ABEKPGPSW06Small} generated in the
 * {@link ABEKPGPSW06SmallSetup}.
 *
 * @author Mirko Jürgens
 */
public class ABEKPGPSW06SmallMasterSecret implements MasterSecret {

    private ZpElement y;

    private Map<Attribute, ZpElement> t;

    public ABEKPGPSW06SmallMasterSecret(ZpElement y, Map<Attribute, ZpElement> t) {
        this.y = y;
        this.t = t;
    }

    public ABEKPGPSW06SmallMasterSecret(Representation repr, ABEKPGPSW06SmallPublicParameters kpp) {
        Zp zp = new Zp(kpp.getGroupG1().size());
        this.y = zp.getElement(repr.obj().get("y"));
        t = new HashMap<Attribute, ZpElement>();
        repr.obj().get("t").map().forEach(entry -> t.put((Attribute) entry.getKey().repr().recreateRepresentable(),
                zp.getElement(entry.getValue())));
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("y", y.getRepresentation());
        MapRepresentation map = new MapRepresentation();
        t.forEach((a, g) -> map.put(new RepresentableRepresentation(a), g.getRepresentation()));

        repr.put("t", map);

        return repr;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABEKPGPSW06SmallMasterSecret other = (ABEKPGPSW06SmallMasterSecret) obj;
        if (t == null) {
            if (other.t != null)
                return false;
        } else if (!t.equals(other.t))
            return false;
        if (y == null) {
            if (other.y != null)
                return false;
        } else if (!y.equals(other.y))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((t == null) ? 0 : t.hashCode());
        result = prime * result + ((y == null) ? 0 : y.hashCode());
        return result;
    }

    public ZpElement getY() {
        return y;
    }

    public Map<Attribute, ZpElement> getT() {
        return t;
    }

}
