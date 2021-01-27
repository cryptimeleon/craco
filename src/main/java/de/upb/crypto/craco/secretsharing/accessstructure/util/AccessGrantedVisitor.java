package de.upb.crypto.craco.secretsharing.accessstructure.util;

import de.upb.crypto.craco.secretsharing.accessstructure.AccessStructure;

import java.util.Set;

/**
 * A visitor that checks whether a given {@link AccessStructure} fulfills the threshold requirement needed
 * to allow access.
 */
public class AccessGrantedVisitor implements Visitor<Boolean> {

    /**
     * The set of party share identifiers that are used to check fulfillment of the access structure.
     * These are the shares that we have and want to compare against the shares required by the node visited by this
     * visitor.
     */
    private final Set<Integer> setOfShares;

    /**
     * Fulfillment threshold of the node visited by this visitor.
     */
    private int threshold;

    /**
     * Number of fulfilled children nodes of the node visited by this visitor.
     */
    private int numberOfFulfilledChildren = 0;

    /**
     * Whether the node visited by this visitor fulfills the threshold requirement.
     */
    private boolean fulfilled;

    /**
     * @param setOfShareIdentifiers set of share identifiers used to check fulfillment of the node to visit
     */
    public AccessGrantedVisitor(Set<Integer> setOfShareIdentifiers) {
        this.setOfShares = setOfShareIdentifiers;
        fulfilled = false;
    }

    /**
     * Internal constructor with additional boolean parameter that indicates if
     * this node is needed for the parent node to be fulfilled (saves runtime).
     *
     * @param setOfShareIdentifiers set of share identifiers used to check fulfillment of the node to visit
     * @param fulfilled initial fulfillment status
     */
    private AccessGrantedVisitor(Set<Integer> setOfShareIdentifiers, boolean fulfilled) {
        this.setOfShares = setOfShareIdentifiers;
        this.fulfilled = fulfilled;
    }

    /**
     * Returns whether the node visited by this visitor fulfills the threshold requirement.
     *
     * @return whether this node is fulfilled
     */
    @Override
    public Boolean getResultOfCurrentNode() {
        return fulfilled;
    }

    @Override
    public Visitor<Boolean> getVisitorForNextChild() {
        return new AccessGrantedVisitor(setOfShares, fulfilled);
    }

    /**
     * Takes information about whether a child is fulfilled and updates fulfillment information of the current
     * node accordingly.
     * If the threshold requirement of the node visited by this visitor is fulfilled,
     * {@code fulfilled} is set to {@code true}.
     *
     * @param isChildFulfilled whether child is fulfilled
     */
    @Override
    public void putResultOfChild(Boolean isChildFulfilled) {
        if (!fulfilled && isChildFulfilled) {
            numberOfFulfilledChildren++;
            fulfilled = (numberOfFulfilledChildren == threshold);
        }
    }

    /**
     * Visits given node and stores its threshold information.
     * If the visited node is a leaf node, it checks whether its share is contained in the set of shares
     * supplied to this visitor and updates {@code fulfilled} accordingly.
     * @param currentNode node of the threshold tree to visit
     */
    @Override
    public void visit(TreeNode currentNode) {
        this.threshold = currentNode.getThreshold();
        // Check if visited node is a leaf node.
        if (threshold == 0)
            if (currentNode instanceof LeafNode)
                fulfilled = setOfShares.contains(((LeafNode) currentNode).getShareIdentifier());
            else
                fulfilled = true;
    }
}
