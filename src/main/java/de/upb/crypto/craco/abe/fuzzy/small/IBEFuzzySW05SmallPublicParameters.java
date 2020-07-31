package de.upb.crypto.craco.abe.fuzzy.small;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * The public parameters for the {@link IBEFuzzySW05Small} generated in
 * the {@link IBEFuzzySW05SmallSetup}.
 *
 * @author Mirko Jürgens
 */
public class IBEFuzzySW05SmallPublicParameters implements PublicParameters {

    @Represented
    private BigInteger d; // identity threshold

    @Represented(restorer = "bilinearGroup::getG1")
    private GroupElement g; // in G_1

    @Represented(restorer = "attr -> bilinearGroup::getG1")
    private Map<Attribute, GroupElement> T; // in G_1

    @Represented(restorer = "bilinearGroup::getGT")
    private GroupElement y; // in G_T

    @Represented
    private BilinearGroup bilinearGroup;

    public IBEFuzzySW05SmallPublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public IBEFuzzySW05SmallPublicParameters() {
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public GroupElement getG() {
        return g;
    }

    public void setG(GroupElement g) {
        this.g = g;
    }

    public Map<Attribute, GroupElement> getT() {
        return T;
    }

    public void setT(Map<Attribute, GroupElement> t2) {
        T = Collections.unmodifiableMap(t2);
    }

    public GroupElement getY() {
        return y;
    }

    public void setY(GroupElement y) {
        this.y = y;
    }

    public Group getGroupG1() {
        return bilinearGroup.getG1();
    }

    public Group getGroupGT() {
        return bilinearGroup.getGT();
    }

    public BilinearMap getE() {
        return bilinearGroup.getBilinearMap();
    }

    public void setBilinearGroup(BilinearGroup bilGroup) {
        this.bilinearGroup = bilGroup;
    }

    @Override
    public int hashCode() {
        return Objects.hash(d, g, T, y , bilinearGroup);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        IBEFuzzySW05SmallPublicParameters other = (IBEFuzzySW05SmallPublicParameters) obj;
        return Objects.equals(d, other.d)
                && Objects.equals(g, other.g)
                && Objects.equals(T, other.T)
                && Objects.equals(y, other.y)
                && Objects.equals(bilinearGroup, other.bilinearGroup);
    }
}
