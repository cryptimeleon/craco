package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * The public parameters for the {@link ABECPWat11Small}, generated in
 * the {@link ABECPWat11SmallSetup}.
 *
 * @author Mirko Jürgens
 */
public class ABECPWat11SmallPublicParameters implements PublicParameters {

    @Represented
    private BilinearGroup bilinearGroup;

    @Represented(restorer = "G1")
    private GroupElement g; // Generator of G_1

    @Represented(restorer = "GT")
    private GroupElement eGGAlpha; // in G_T

    @Represented(restorer = "G1")
    private GroupElement gA; // in G_1

    @Represented(restorer = "foo -> G1")
    private Map<Attribute, GroupElement> h; // Attribute in Universe, Element in
    // G_1

    public ABECPWat11SmallPublicParameters() {
    }

    public ABECPWat11SmallPublicParameters(Representation repr) {
        bilinearGroup = (BilinearGroup) repr.obj().get("bilinearGroup").repr().recreateRepresentable();
        new ReprUtil(this).register(bilinearGroup).deserialize(repr);
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

    public GroupElement getG() {
        return g;
    }

    public void setG(GroupElement g) {
        this.g = g;
    }

    public GroupElement geteGGAlpha() {
        return eGGAlpha;
    }

    public void seteGGAlpha(GroupElement eGGAlpha) {
        this.eGGAlpha = eGGAlpha;
    }

    public GroupElement getgA() {
        return gA;
    }

    public void setgA(GroupElement gA) {
        this.gA = gA;
    }

    public Map<Attribute, GroupElement> getH() {
        return h;
    }

    public void setH(Map<Attribute, GroupElement> h) {
        this.h = Collections.unmodifiableMap(h);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bilinearGroup, g, eGGAlpha, gA, h);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ABECPWat11SmallPublicParameters other = (ABECPWat11SmallPublicParameters) obj;
        return Objects.equals(bilinearGroup, other.bilinearGroup)
                && Objects.equals(g, other.g)
                && Objects.equals(eGGAlpha, other.eGGAlpha)
                && Objects.equals(gA, other.gA)
                && Objects.equals(h, other.h);
    }

}
