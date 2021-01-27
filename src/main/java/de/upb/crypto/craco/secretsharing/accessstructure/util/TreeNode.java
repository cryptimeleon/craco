package de.upb.crypto.craco.secretsharing.accessstructure.util;

import de.upb.crypto.craco.secretsharing.accessstructure.exception.WrongAccessStructureException;

/**
 * A node in a threshold tree.
 */
public interface TreeNode {

    /**
     * Returns the number of children of this node.
     */
    public int getNumberOfChildren();

    /**
     * Returns the threshold value of this node. If this node is a
     * leaf, the value must be 0.
     */
    public int getThreshold();

    /**
     * Uses the given {@code Visitor} on this tree node.
     *
     * @param <F> type of the return result of the visitor
     * @param visitor the visitor to use
     * @return the result of visiting this node
     * @throws WrongAccessStructureException if something is wrong with the access structure being traversed
     */
    public <F> F performVisitor(Visitor<F> visitor)
            throws WrongAccessStructureException;
}
