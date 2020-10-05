package de.upb.crypto.craco.abe.ibe;

import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Arrays;
import java.util.Objects;

/**
 * The {@link CiphertextIndex} for {@link FullIdent}.
 *
 * @author Marius Dransfeld, Refactoring: Mirko Jürgens
 */
public class FullIdentCipherText implements CipherText {

    @Represented(restorer = "G1")
    private GroupElement u; // P^r \in G1

    @Represented
    private byte[] v; // sigma \oplus H_2(g_id^r)

    @Represented
    private byte[] w; // M \oplus H_4(sigma)

    public FullIdentCipherText(GroupElement U, byte[] V, byte[] W) {
        this.u = U;
        this.v = V;
        this.w = W;
    }

    public FullIdentCipherText(Representation repr, FullIdentPublicParameters pp) {
        new ReprUtil(this).register(pp.getGroupG1(), "G1").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getU() {
        return u;
    }

    public byte[] getV() {
        return v;
    }

    public byte[] getW() {
        return w;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((u == null) ? 0 : u.hashCode());
        result = prime * result + Arrays.hashCode(v);
        result = prime * result + Arrays.hashCode(w);
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
        FullIdentCipherText other = (FullIdentCipherText) obj;
        return Objects.equals(u, other.u)
                && Arrays.equals(v, other.v)
                && Arrays.equals(w, other.w);
    }
}
