package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;

/**
 * @author pschleiter, Fabian Eidens (refactoring)
 */
public class LeafNode implements TreeNode {

    /**
     * The leaf nodes in this tree are numbered 0,...,n-1.
     */
    private int identifier;

    /**
     * create a new leaf
     *
     * @param attribute that is represented by this leaf
     * @param value     additional information to the attribute
     */
    public LeafNode(Integer value) {
        this.identifier = value;
    }

    /**
     * The leaf nodes in this tree correspond to shares, which are numbered 0,...,n-1.
     */
    public int getShareIdentifier() {
        return identifier;
    }

    @Override
    public int getNumberOfChildren() {
        return 0;
    }

    @Override
    public int getThreshold() {
        return 0;
    }

    @Override
    public <F> F performVisitor(Visitor<F> visitor) throws WrongAccessStructureException {
        visitor.visit(this);

        return visitor.getResultOfCurrentNode();
    }

    @Override
    public String toString() {
        return String.valueOf(identifier);
    }
}
