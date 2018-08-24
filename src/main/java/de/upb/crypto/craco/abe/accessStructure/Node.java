package de.upb.crypto.craco.abe.accessStructure;

import java.util.List;

public interface Node {

    public static final int NODETYPE_ATTRIBUTE = 1;
    public static final int NODETYPE_AND = 2;
    public static final int NODETYPE_OR = 3;
    public static final int NODETYPE_TRESHOLD = 4;

    /**
     * @return all Childs of the Node
     */
    public List<Node> getChilds();

    /**
     * @return the parent of the node, null if it is root
     */
    public Node getNodeParent();

    /**
     * @return NODETYPE_ATTRIBUTE or NODETYPE_AND or NODETYPE_OR or
     * NODETYPE_TRESHOLD
     */
    public int getType();

}
