package de.upb.crypto.craco.abe.kp.large;

import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.kem.abe.kp.large.ABEKPGPSW06KEMCipherText;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Map;

/**
 * A {@link CipherText} for the {@link ABEKPGPSW06}.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens, Denis Diemert
 */
public class ABEKPGPSW06CipherText extends ABEKPGPSW06KEMCipherText {
    /**
     * E' := m * Y^s \in G_T
     */
    @Represented(structure = "groupGT", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement ePrime;

    @SuppressWarnings("unused")
    private Group groupGT;

    public ABEKPGPSW06CipherText(GroupElement ePrime, GroupElement eTwoPrime, Map<Attribute, GroupElement> eElementMap,
                                 SetOfAttributes attributes) {
        super(attributes, eTwoPrime, eElementMap);
        this.ePrime = ePrime;
    }

    public ABEKPGPSW06CipherText(Representation representation, ABEKPGPSW06PublicParameters kpp) {
        // restoring doesn't work with super call, so empty constructor is needed
        super();
        groupG1 = kpp.getGroupG1();
        groupGT = kpp.getGroupGT();
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public GroupElement getEPrime() {
        return ePrime;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof ABEKPGPSW06CipherText)) {
            return false;
        }
        ABEKPGPSW06CipherText other = (ABEKPGPSW06CipherText) o;
        return super.equals(other) && ePrime.equals(other.ePrime);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((ePrime == null) ? 0 : ePrime.hashCode());
        return result;
    }

}
