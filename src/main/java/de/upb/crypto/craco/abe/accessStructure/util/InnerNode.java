package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;

import java.util.ArrayList;
import java.util.stream.Collectors;

/**
 * @param <E> type of the attribute
 * @author pschleiter, Fabian Eidens (refactoring)
 */
public class InnerNode implements TreeNode {

    /**
     * children of this inner node
     */
    private ArrayList<TreeNode> children;

    /**
     * the threshold value of this node
     */
    private int t;

    /**
     * creates a new inner node
     */
    public InnerNode() {
        children = new ArrayList<TreeNode>();
        t = 0;
    }

    /**
     * creates a new inner node
     *
     * @param children
     * @param threshold
     */
    public InnerNode(ArrayList<TreeNode> children, Integer threshold) {
        this.children = children;
        this.t = threshold;
    }

    /**
     * appends a child to the children of this tree
     *
     * @param child
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
