package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;

/**
 * Interface specifying the methods any visitor for a threshold tree should implement
 * (created out of the extended boolean formula).
 * <p>
 * Usage of the visitor is done via {@link TreeNode#performVisitor(Visitor)}.
 *
 * @param <F> type of the return value of the function
 *            {@link Visitor#getResultOfCurrentNode()}
 */
public interface Visitor<F> {

    /**
     * Returns the value that was calculated during {@link Visitor#visit(TreeNode)}.
     *
     * @throws WrongAccessStructureException if something is wrong with the access structure being traversed
     */
    F getResultOfCurrentNode() throws WrongAccessStructureException;

    /**
     * Returns a visitor for the next child. The resulting visitor is functionally the same, but any state that was
     * mutated while visiting the current child may be reset.
     *
     * @return a visitor of the same kind
     * @throws WrongAccessStructureException if something is wrong with the access structure being traversed
     */
    Visitor<F> getVisitorForNextChild()
            throws WrongAccessStructureException;

    /**
     * Inserts the result of the child of current node, so that the current
     * visitor can calculate its own value from it.
     *
     * @param input the result of visiting the child of the node currently being visited
     */
    void putResultOfChild(F input);

    /**
     * Performs some kind of computation on the given {@code currentNode}.
     *
     * @param currentNode node of the threshold tree to visit
     * @throws WrongAccessStructureException if something is wrong with the access structure being traversed
     */
    void visit(TreeNode currentNode)
            throws WrongAccessStructureException;
}
