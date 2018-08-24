package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;

public class ToStringVisitor implements Visitor<String> {

    String output = new String();

    TreeNode currentNode;

    boolean firstAttr = true;

    public ToStringVisitor() {
    }

    @Override
    public String getResultOfCurrentNode() throws WrongAccessStructureException {
        if (currentNode.getNumberOfChildren() == 0) {
            TreeNode leaf = currentNode;
            return leaf.toString();
        } else {
            return output.concat(String.format("' %d )",
                    currentNode.getThreshold()));
        }
    }

    @Override
    public Visitor<String> getVisitorForNextChild()
            throws WrongAccessStructureException {
        return new ToStringVisitor();
    }

    @Override
    public void putResultOfChild(String input) {
        if (firstAttr) {
            output = output.concat(String.format("%s", input));
            firstAttr = false;
        } else
            output = output.concat(String.format(", %s", input));
    }

    @Override
    public void visit(TreeNode currentNode)
            throws WrongAccessStructureException {
        this.currentNode = currentNode;
        output = new String("( ");
    }

}
