package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;

/**
 * This is a implementation of the visitor performed on the threshold tree
 * (created out of the extended boolean formula)
 *
 * @param <F> Type of the returning value of the function
 *            <code>getResultOfCurrentNode</code>
 * @author pschleiter
 */
public interface Visitor<F> {

    /**
     * Returns the value, that is eventually calculated during the method visit.
     *
     * @return
     * @throws WrongAccessStructureException
     */
    public F getResultOfCurrentNode() throws WrongAccessStructureException;

    /**
     * return a visitor for the next child. Then this child will be called with
     * this visitor.
     *
     * @return a visitor of the same kind
     * @throws WrongAccessStructureException
     */
    public Visitor<F> getVisitorForNextChild()
            throws WrongAccessStructureException;

    /**
     * Insert the result of the child of current node, so that the current
     * visitor can calculate out of it, its own value.
     *
     * @param input
     */
    public void putResultOfChild(F input);

    /**
     * method, that will performed on <code>currentNode</code>
     *
     * @param currentNode node of the threshold tree
     * @throws WrongAccessStructureException
     */
    public void visit(TreeNode currentNode)
            throws WrongAccessStructureException;
}
