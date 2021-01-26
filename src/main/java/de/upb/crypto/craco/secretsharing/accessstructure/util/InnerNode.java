package de.upb.crypto.craco.secretsharing.accessstructure.util;

import de.upb.crypto.craco.secretsharing.accessstructure.exception.WrongAccessStructureException;

import java.util.ArrayList;
import java.util.stream.Collectors;

/**
 * An inner node of a threshold tree.
 *
 * @author pschleiter, Fabian Eidens (refactoring)
 */
public class InnerNode implements TreeNode {

    /**
     * The children of this inner node.
     */
    private final ArrayList<TreeNode> children;

    /**
     * The threshold value of this node.
     */
    private int t;

    /**
     * Creates a new inner node with no children and threshold set to 0.
     */
    public InnerNode() {
        children = new ArrayList<>();
        t = 0;
    }

    /**
     * Creates a new inner node with the given children and trreshold.
     *
     * @param children the children of this inner node
     * @param threshold the threshold of this node
     */
    public InnerNode(ArrayList<TreeNode> children, Integer threshold) {
        this.children = children;
        this.t = threshold;
    }

    /**
     * Appends a child to the children of this node.
     *
     * @param child the child to add
     */
    public void addChild(TreeNode child) {
        children.add(child);
    }

    public ArrayList<TreeNode> getChildren() {
        return new ArrayList<>(children);
    }

    @Override
    public int getNumberOfChildren() {
        return children.size();
    }

    @Override
    public int getThreshold() {
        return t;
    }

    /**
     * Visits the threshold tree represented by this inner node in pre-order.
     * <p>
     * For each child, a new visitor is created via {@link Visitor#getVisitorForNextChild()} which is
     * used to visit the child.
     * The result of those visits are then used to calculate the result of the visitor vising this node.
     *
     * @param visitor the visitor to use
     * @param <F> the return result of the visitor
     * @return the result returned by the visitor visiting this node
     * @throws WrongAccessStructureException if something is wrong with the access structure being traversed
     */
    @Override
    public <F> F performVisitor(Visitor<F> visitor) throws WrongAccessStructureException {

        visitor.visit(this);

        for (TreeNode child : children) {
            Visitor<F> childVisitor = visitor.getVisitorForNextChild();
            F childResult = child.performVisitor(childVisitor);
            visitor.putResultOfChild(childResult);
        }

        return visitor.getResultOfCurrentNode();
    }

    public void setThreshold(Integer threshold) {
        t = threshold;
    }

    @Override
    public String toString() {
        return "( " + getThreshold() + " of: " + children.stream().map(Object::toString)
                .collect(Collectors.joining(",")) + " )";
    }
}
