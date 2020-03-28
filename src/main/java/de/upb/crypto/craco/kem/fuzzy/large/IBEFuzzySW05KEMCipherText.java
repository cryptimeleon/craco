package de.upb.crypto.craco.kem.fuzzy.large;

import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05;
import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05PublicParameters;
import de.upb.crypto.craco.abe.fuzzy.large.IBEIBEFuzzySW05SW05CipherText;
import de.upb.crypto.craco.abe.fuzzy.large.Identity;
import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedMap;

import java.math.BigInteger;
import java.util.Map;

/**
 * A ciphertext for a key generated by {@link IBEFuzzySW05KEM}. It essentially is a ciphertext of the
 * {@link IBEFuzzySW05}, but leaving out the component {@link IBEIBEFuzzySW05SW05CipherText#getEPrime()}.
 * This is because the component {@code ePrime} is output as the key.
 *
 * @author Denis Diemert (based on {@link IBEIBEFuzzySW05SW05CipherText})
 */
public class IBEFuzzySW05KEMCipherText implements CipherText {
    /**
     * ciphertext's identity \omega'
     */
    @Represented
    private Identity omegaPrime;

    /**
     * E'' \in G_1
     */
    @Represented(structure = "groupG1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    protected GroupElement eTwoPrime;

    /**
     * values E_i \in G_1 for {@link BigInteger}'s i \in {@link #omegaPrime}
     */
    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented(structure = "groupG1", recoveryMethod =
            GroupElement.RECOVERY_METHOD))
    protected Map<BigInteger, GroupElement> eElementMap;

    @SuppressWarnings("unused")
    protected Group groupG1;

    public IBEFuzzySW05KEMCipherText(Identity omegaPrime, GroupElement eTwoPrime,
                                     Map<BigInteger, GroupElement> eElementMap) {
        this.omegaPrime = omegaPrime;
        this.eTwoPrime = eTwoPrime;
        this.eElementMap = eElementMap;
    }

    public IBEFuzzySW05KEMCipherText(Representation repr, IBEFuzzySW05PublicParameters pp) {
        groupG1 = pp.getGroupG1();
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    public IBEFuzzySW05KEMCipherText() {

    }

    public Identity getOmegaPrime() {
        return omegaPrime;
    }

    public GroupElement getETwoPrime() {
        return eTwoPrime;
    }

    public Map<BigInteger, GroupElement> getEElementMap() {
        return eElementMap;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        IBEFuzzySW05KEMCipherText that = (IBEFuzzySW05KEMCipherText) o;

        if (omegaPrime != null ? !omegaPrime.equals(that.omegaPrime) : that.omegaPrime != null)
            return false;
        if (eTwoPrime != null ? !eTwoPrime.equals(that.eTwoPrime) : that.eTwoPrime != null)
            return false;
        return eElementMap != null ? eElementMap.equals(that.eElementMap) : that.eElementMap == null;
    }

    @Override
    public int hashCode() {
        int result = omegaPrime != null ? omegaPrime.hashCode() : 0;
        result = 31 * result + (eTwoPrime != null ? eTwoPrime.hashCode() : 0);
        result = 31 * result + (eElementMap != null ? eElementMap.hashCode() : 0);
        return result;
    }
}
