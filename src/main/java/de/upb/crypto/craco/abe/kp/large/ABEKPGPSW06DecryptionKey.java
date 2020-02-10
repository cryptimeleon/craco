package de.upb.crypto.craco.abe.kp.large;

import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

import java.math.BigInteger;
import java.util.Map;

/**
 * A {@link DecryptionKey} for the {@link ABEKPGPSW06} that stores a {@link Policy} as {@link KeyIndex}.
 * <p>
 * This key should be created by
 * {@link ABEKPGPSW06#generateDecryptionKey(de.upb.crypto.craco.common.interfaces.pe.MasterSecret, KeyIndex)}
 *
 * @author Mirko Jürgens, refactoring: Denis Diemert
 */
public class ABEKPGPSW06DecryptionKey implements DecryptionKey {
    @Represented
    private Policy policy;

    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "groupG1", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    private Map<BigInteger, GroupElement> dElementMap;

    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "groupG1", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    private Map<BigInteger, GroupElement> rElementMap;

    @SuppressWarnings("unused")
    private Group groupG1;

    public ABEKPGPSW06DecryptionKey(Policy policy, Map<BigInteger, GroupElement> dElementMap,
                                    Map<BigInteger, GroupElement> rElementMap) {
        this.policy = policy;
        this.dElementMap = dElementMap;
        this.rElementMap = rElementMap;
    }

    public ABEKPGPSW06DecryptionKey(Representation repr, ABEKPGPSW06PublicParameters kpp) {
        groupG1 = kpp.getGroupG1();
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public Policy getPolicy() {
        return policy;
    }

    public Map<BigInteger, GroupElement> getDElementMap() {
        return dElementMap;
    }

    public Map<BigInteger, GroupElement> getRElementMap() {
        return rElementMap;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((dElementMap == null) ? 0 : dElementMap.hashCode());
        result = prime * result + ((rElementMap == null) ? 0 : rElementMap.hashCode());
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
        ABEKPGPSW06DecryptionKey other = (ABEKPGPSW06DecryptionKey) obj;
        if (dElementMap == null) {
            if (other.dElementMap != null)
                return false;
        } else if (!dElementMap.equals(other.dElementMap))
            return false;
        if (rElementMap == null) {
            if (other.rElementMap != null)
                return false;
        } else if (!rElementMap.equals(other.rElementMap))
            return false;
        if (policy == null) {
            if (other.policy != null)
                return false;
        } else if (!policy.equals(other.policy))
            return false;
        return true;
    }

}
