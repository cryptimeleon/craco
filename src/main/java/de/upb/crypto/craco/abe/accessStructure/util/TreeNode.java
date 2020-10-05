package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;

/**
 * Light interface for an implementation of an threshold tree.
 *
 * @author pschleiter, Fabian Eidens (refactor)
 */
public interface TreeNode {

    /**
     * Returns the number of children of the current node.
     *
     * @return
     */
    public int getNumberOfChildren();

    /**
     * Returns the threshold value of the current node. If the current node is a
     * leaf the value will be 0.
     */
    public int getThreshold();

    /**
     * Implements the visitor pattern in preorder where additionally on every
     * child is performed an <code>getResultOfCurrentNode</code> and then the
     * result is used as input for <code>putResultOfChild</code>
     *
     * @param <F>
     * @param visitor
     * @return
     * @throws WrongAccessStructureException
     */
    public <F> F performVisitor(Visitor<F> visitor)
            throws WrongAccessStructureException;
}
