package de.upb.crypto.craco.abe.fuzzy.small;

import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

import java.util.Map;

/**
 * The {@link CipherText} for the {@link IBEFuzzySW05Small}
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens
 */
public class IBEFuzzySW05SmallCipherText implements CipherText {

    @Represented
    private SetOfAttributes omega_prime;

    // in G_T
    @Represented(structure = "groupGT", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement e_prime;

    // in G_1
    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "groupG1", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    private Map<Attribute, GroupElement> e;


    @SuppressWarnings("unused")
    private Group groupG1;

    @SuppressWarnings("unused")
    private Group groupGT;


    public IBEFuzzySW05SmallCipherText(SetOfAttributes identity, GroupElement E_prime,
                                       Map<Attribute, GroupElement> e2) {
        this.omega_prime = identity;
        this.e_prime = E_prime;
        this.e = e2;
    }

    public IBEFuzzySW05SmallCipherText(Representation repr, IBEFuzzySW05SmallPublicParameters pp) {
        groupGT = pp.getGroupGT();
        groupG1 = pp.getGroupG1();
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public SetOfAttributes getOmega_prime() {
        return omega_prime;
    }

    public GroupElement getE_prime() {
        return e_prime;
    }

    public Map<Attribute, GroupElement> getE() {
        return e;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((e == null) ? 0 : e.hashCode());
        result = prime * result + ((e_prime == null) ? 0 : e_prime.hashCode());
        result = prime * result + ((omega_prime == null) ? 0 : omega_prime.hashCode());
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
        IBEFuzzySW05SmallCipherText other = (IBEFuzzySW05SmallCipherText) obj;
        if (e == null) {
            if (other.e != null)
                return false;
        } else if (!e.equals(other.e))
            return false;
        if (e_prime == null) {
            if (other.e_prime != null)
                return false;
        } else if (!e_prime.equals(other.e_prime))
            return false;
        if (omega_prime == null) {
            if (other.omega_prime != null)
                return false;
        } else if (!omega_prime.containsAll(other.omega_prime) || !other.omega_prime.containsAll(omega_prime))
            return false;
        return true;
    }
}
