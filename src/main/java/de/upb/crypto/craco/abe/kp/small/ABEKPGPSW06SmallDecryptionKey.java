package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.*;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link DecryptionKey} for the {@link ABEKPGPSW06Small} that
 * stores a {@link Policy} as {@link KeyIndex}.
 * <p>
 * This key should be created by
 * {@link ABEKPGPSW06Small#generateDecryptionKey(de.upb.crypto.craco.common.interfaces.pe.MasterSecret, KeyIndex)}
 *
 * @author Mirko Jürgens
 */
public class ABEKPGPSW06SmallDecryptionKey implements DecryptionKey {

    private Policy policy;
    private Map<BigInteger, GroupElement> D;

    public ABEKPGPSW06SmallDecryptionKey(Policy policy, Map<BigInteger, GroupElement> d) {
        this.policy = policy;
        this.D = d;
    }

    public ABEKPGPSW06SmallDecryptionKey(Representation repr, ABEKPGPSW06SmallPublicParameters kpp) {
        D = new HashMap<BigInteger, GroupElement>();
        repr.obj().get("D").map().getMap()
                .forEach((key, value) -> D.put(key.bigInt().get(), kpp.getGroupG1().getElement(value)));
        policy = (Policy) repr.obj().get("policy").repr().recreateRepresentable();
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("policy", new RepresentableRepresentation(policy));
        MapRepresentation tRepr = new MapRepresentation();
        D.forEach((key, value) -> tRepr.put(new BigIntegerRepresentation(key), value.getRepresentation()));
        repr.put("D", tRepr);
        return repr;
    }

    public Policy getPolicy() {
        return policy;
    }

    public Map<BigInteger, GroupElement> getD() {
        return D;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((D == null) ? 0 : D.hashCode());
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
        ABEKPGPSW06SmallDecryptionKey other = (ABEKPGPSW06SmallDecryptionKey) obj;
        if (D == null) {
            if (other.D != null)
                return false;
        } else if (!D.equals(other.D))
            return false;
        if (policy == null) {
            if (other.policy != null)
                return false;
        } else if (!policy.equals(other.policy))
            return false;
        return true;
    }

}
