package org.cryptimeleon.craco.sig.sps.groth15;

import org.cryptimeleon.craco.sig.SigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zp;
import org.cryptimeleon.math.structures.rings.zn.Zp.ZpElement;

import java.util.Objects;

/**
 * Class for the secret (signing) key of the SPS-EQ signature scheme.
 *
 *
 */

public class SPSGroth15SigningKey implements SigningKey {

    /**
     * v \in Z_p^* in paper.
     */
    @Represented(restorer="Zp")
    protected ZpElement exponentV;

    @Represented(restorer = "scheme::restoreVerificationKey")
    protected SPSGroth15VerificationKey pk;

    public SPSGroth15SigningKey() {
        super();
    }

    public SPSGroth15SigningKey(Representation repr, Zp zp, SPSGroth15SignatureScheme scheme) {
        new ReprUtil(this).register(zp, "Zp").register(scheme, "scheme").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public ZpElement getExponentV() {
        return exponentV;
    }

    public void setExponentV(ZpElement exponentV) {
        this.exponentV = exponentV;
    }

    public int getNumberOfMessages() {
        return pk.getNumberOfMessages();
    }

    public SPSGroth15VerificationKey getPk() {
        return pk;
    }

    public void setPk(SPSGroth15VerificationKey pk) {
        this.pk = pk;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SPSGroth15SigningKey that = (SPSGroth15SigningKey) o;
        return Objects.equals(exponentV, that.exponentV)
                && Objects.equals(pk, that.pk);
    }

    @Override
    public int hashCode() {
        return Objects.hash(exponentV, pk);
    }
}
