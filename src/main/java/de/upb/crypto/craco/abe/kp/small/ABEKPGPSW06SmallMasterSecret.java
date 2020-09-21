package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.pe.MasterSecret;
import de.upb.crypto.math.serialization.MapRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.RepresentableRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The master secret for the {@link ABEKPGPSW06Small} generated in the
 * {@link ABEKPGPSW06SmallSetup}.
 *
 * @author Mirko Jürgens
 */
public class ABEKPGPSW06SmallMasterSecret implements MasterSecret {

    @Represented(restorer = "Zp")
    private ZpElement y;

    @Represented(restorer = "attr -> Zp")
    private Map<Attribute, ZpElement> t;

    public ABEKPGPSW06SmallMasterSecret(ZpElement y, Map<Attribute, ZpElement> t) {
        this.y = y;
        this.t = t;
    }

    public ABEKPGPSW06SmallMasterSecret(Representation repr, ABEKPGPSW06SmallPublicParameters kpp) {
        new ReprUtil(this).register(new Zp(kpp.getGroupG1().size()), "Zp").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
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
        return Objects.equals(t, other.t)
                && Objects.equals(y, other.y);
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
