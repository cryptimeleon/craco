package de.upb.crypto.craco.abe.fuzzy.large;

import de.upb.crypto.craco.interfaces.pe.MasterSecret;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

/**
 * The {@link MasterSecret} of the {@link IBEFuzzySW05} generated
 * in the {@link IBEFuzzySW05Setup}.
 *
 * @author Mirko Jürgens
 */
public class IBEFuzzySW05MasterSecret implements MasterSecret {

    @Represented(structure = "zp", recoveryMethod = ZpElement.RECOVERY_METHOD)
    private ZpElement y;

    @SuppressWarnings("unused")
    private Zp zp;

    public IBEFuzzySW05MasterSecret(ZpElement y) {
        this.y = y;
    }

    public IBEFuzzySW05MasterSecret(Representation repr, IBEFuzzySW05PublicParameters kpp) {
        zp = new Zp(kpp.getGroupG1().size());
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        IBEFuzzySW05MasterSecret other = (IBEFuzzySW05MasterSecret) obj;
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
        result = prime * result + ((y == null) ? 0 : y.hashCode());
        return result;
    }

    public ZpElement getY() {
        return y;
    }

}
