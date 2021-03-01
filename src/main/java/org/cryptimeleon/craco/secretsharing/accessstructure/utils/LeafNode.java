package org.cryptimeleon.craco.secretsharing.accessstructure.utils;

import org.cryptimeleon.craco.secretsharing.accessstructure.exceptions.WrongAccessStructureException;
import org.cryptimeleon.craco.secretsharing.accessstructure.visitors.Visitor;

/**
 * A leaf node in a threshold tree, a node without children and threshold set to 0.
 *
 *
 */
public class LeafNode implements TreeNode {

    /**
     * The integer identifying this leaf node whose value lies between 0 and n-1 (inclusive).
     */
    private final int identifier;

    /**
     * Creates a new leaf.
     *
     * @param value the identifier of the new leaf between 0 and n-1 (inclusive)
     */
    public LeafNode(Integer value) {
        this.identifier = value;
    }

    /**
     * The leaf nodes in this tree correspond to shares.
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
