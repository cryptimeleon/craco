package de.upb.crypto.craco.abe.fuzzy.large;

import de.upb.crypto.craco.kem.fuzzy.large.IBEFuzzySW05KEMCipherText;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Map;

/**
 * Ciphertext for {@link IBEFuzzySW05}.
 * <p>
 * It extends {@link IBEFuzzySW05KEMCipherText} by the component {@link #ePrime}.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens, Denis Diemert
 */
public class IBEIBEFuzzySW05SW05CipherText extends IBEFuzzySW05KEMCipherText {

    /**
     * E' \in G_1
     */
    @Represented(structure = "groupGT", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement ePrime;

    @SuppressWarnings("unused")
    Group groupGT;

    public IBEIBEFuzzySW05SW05CipherText(Identity omegaPrime, GroupElement ePrime, GroupElement eTwoPrime,
                                         Map<BigInteger, GroupElement> e) {
        super(omegaPrime, eTwoPrime, e);
        this.ePrime = ePrime;
    }

    public IBEIBEFuzzySW05SW05CipherText(Representation repr, IBEFuzzySW05PublicParameters pp) {
        // restoring doesn't work with super call, so empty constructor is needed
        super();
        groupG1 = pp.getGroupG1();
        groupGT = pp.getGroupGT();
        new ReprUtil(this).deserialize(repr);
    }

    public GroupElement getEPrime() {
        return ePrime;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof IBEIBEFuzzySW05SW05CipherText)) {
            return false;
        }
        IBEIBEFuzzySW05SW05CipherText other = (IBEIBEFuzzySW05SW05CipherText) o;
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
