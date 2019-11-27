package de.upb.crypto.craco.sig.ps18;

import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import java.util.Arrays;
import java.util.Objects;

public class PS18VerificationKeyPrec implements VerificationKey {

    /**
     * \tilde{g} in paper.
     */
    @Represented(restorer = "G2")
    private GroupElement group2ElementTildeG;

    /**
     * \tilde{X} in paper.
     */
    @Represented(restorer = "G2")
    private GroupElement group2ElementTildeX;

    /**
     * \tilde{Y_1}, ..., \tilde{Y_{r+1}} in paper.
     */
    @Represented(restorer = "[G2]")
    private GroupElement[] group2ElementsTildeYi;

    /**
     * Precomputed expression for left pairing, group 2.
     */
    // TODO: Does representation work for expressions?
    @Represented()
    private GroupElementExpression leftGroup2ElemExpr;

    public PS18VerificationKeyPrec(GroupElement group2ElementTildeG,
                                   GroupElement group2ElementTildeX,
                                   GroupElement[] group2ElementsTildeYi,
                                   GroupElementExpression leftGroup2ElemExpr) {
        this.group2ElementTildeG = group2ElementTildeG;
        this.group2ElementTildeX = group2ElementTildeX;
        this.group2ElementsTildeYi = group2ElementsTildeYi;
        this.leftGroup2ElemExpr = leftGroup2ElemExpr;
    }

    /**
     * Constructs verification key from a representation and the bilinear group
     * used in the public parameters.
     *
     * @param repr The representation to construct the verification key from.
     * @param group2 Group G2 of the bilinear group used in the public parameters.
     */
    public PS18VerificationKeyPrec(Representation repr, Group group2) {
        new ReprUtil(this).register(group2, "G2").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public GroupElement getGroup2ElementTildeG() {
        return group2ElementTildeG;
    }

    public void setGroup2ElementTildeG(GroupElement group2ElementTildeG) {
        this.group2ElementTildeG = group2ElementTildeG;
    }

    public GroupElement getGroup2ElementTildeX() {
        return group2ElementTildeX;
    }

    public void setGroup2ElementTildeX(GroupElement group2ElementTildeX) {
        this.group2ElementTildeX = group2ElementTildeX;
    }

    public GroupElement[] getGroup2ElementsTildeYi() {
        return group2ElementsTildeYi;
    }

    public void setGroup2ElementsTildeYi(GroupElement[] group2ElementsTildeYi) {
        this.group2ElementsTildeYi = group2ElementsTildeYi;
    }

    public void setLeftGroup2ElemExpr(GroupElementExpression leftGroup2ElemExpr) {
        this.leftGroup2ElemExpr = leftGroup2ElemExpr;
    }

    public GroupElementExpression getLeftGroup2ElemExpr() {
        return leftGroup2ElemExpr;
    }

    public int getNumberOfMessages() {
        return group2ElementsTildeYi.length - 1;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PS18VerificationKeyPrec that = (PS18VerificationKeyPrec) o;
        // TODO: does equals work for expressions?
        return Objects.equals(group2ElementTildeG, that.group2ElementTildeG)
                && Objects.equals(group2ElementTildeX, that.group2ElementTildeX)
                && Arrays.equals(group2ElementsTildeYi, that.group2ElementsTildeYi)
                && leftGroup2ElemExpr.equals(that.leftGroup2ElemExpr);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(group2ElementTildeG, group2ElementTildeX);
        result = 31 * result + Arrays.hashCode(group2ElementsTildeYi);
        // TODO: Do expressions have sensible hash code?
        result = 31 * result + leftGroup2ElemExpr.hashCode();
        return result;
    }
}
