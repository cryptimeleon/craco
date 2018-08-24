package de.upb.crypto.craco.abe.accessStructure.util;

import java.util.Set;

/**
 * @author pschleiter
 */
public class AccessGrantedVisitor implements Visitor<Boolean> {

    /**
     * the set of shares for that it will be checked whether they fulfill the
     * access structure or not
     */
    private Set<Integer> setOfShares;

    /**
     * threshold of the node on that this instance is performed
     */
    private int threshold;

    /**
     * number of children on that {@link TreeNode.performVisitor} was called an
     * that are fulfilled.
     */
    private int numberOfFulfilledChildren = 0;

    /**
     * indicates if current node is fulfilled until now or not
     */
    private boolean fulfilled;

    /**
     * Creates a new Visitor with the <code>setOfParties</code>
     *
     * @param setOfParties
     */
    public AccessGrantedVisitor(Set<Integer> setOfParties) {
        this.setOfShares = setOfParties;
        fulfilled = false;
    }

    /**
     * Internal constructer with additional boolean parameter, that indicates if
     * this node is need for the parent node to be fulfilled (save runtime)
     *
     * @param setOfShareIdentifiers
     * @param fulfilled
     */
    private AccessGrantedVisitor(Set<Integer> setOfShareIdentifiers, boolean fulfilled) {
        this.setOfShares = setOfShareIdentifiers;
        this.fulfilled = fulfilled;
    }

    @Override
    public Boolean getResultOfCurrentNode() {
        return new Boolean(fulfilled);
    }

    @Override
    public Visitor<Boolean> getVisitorForNextChild() {
        return new AccessGrantedVisitor(setOfShares, fulfilled);
    }

    @Override
    public void putResultOfChild(Boolean input) {
        if (!fulfilled && input) {
            numberOfFulfilledChildren++;
            fulfilled = (numberOfFulfilledChildren == threshold);
        }
    }

    @Override
    public void visit(TreeNode currentNode) {
        this.threshold = currentNode.getThreshold();
        if (threshold == 0)
            if (currentNode instanceof LeafNode)
                fulfilled = setOfShares.contains(((LeafNode) currentNode).getShareIdentifier());
            else
                fulfilled = true;
    }

}
