package de.upb.crypto.craco.secretsharing;

import de.upb.crypto.craco.abe.accessStructure.exception.NoSatisfyingSet;
import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.craco.abe.interfaces.LinearSecretSharing;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.PolicyFact;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * A {@link ThresholdTreeSecretSharing} is a {@link LinearSecretSharing} which shares a secret not only among a single
 * {@link ThresholdPolicy}'s children, but among a whole tree of {@link ThresholdPolicy}.
 * That way a secret can be shared among complex expression represented by a hierarchy of {@link ThresholdPolicy}.
 * <p>
 * It is assumed that each inner node of the hierarchy is a {@link ThresholdPolicy} and each leaf implements
 * both {@link Policy} and {@link PolicyFact}.
 */
public class ThresholdTreeSecretSharing implements LinearSecretSharing<Policy>, StandaloneRepresentable {

    private static final Logger log = Logger.getLogger(ThresholdTreeSecretSharing.class.getName());

    @Represented
    private SecretSharingSchemeProvider lsssInstanceProvider;
    @Represented
    private Zp field;
    @Represented
    private ThresholdPolicy rootThresholdPolicy;

    private InnerSecretSharingNode secretSharingTree;
    private Map<Integer, Policy> shareReceiverMap = new LinkedHashMap<>();


    /**
     * Create a new {@link ThresholdTreeSecretSharing} instance.
     *
     * @param policy               root node of the {@link ThresholdPolicy} tree to share the secret among
     * @param field                {@link Zp} over which the secret shall be shared
     * @param lsssInstanceProvider {@link SecretSharingSchemeProvider} to be used for construction of the
     *                             {@link LinearSecretSharing} instances for the tree's inner nodes
     * @throws IllegalArgumentException if the given {@link ThresholdPolicy} contains any node which is neither a
     *                                  {@link ThresholdPolicy} nor a {@link PolicyFact}
     */
    public ThresholdTreeSecretSharing(ThresholdPolicy policy, Zp field,
                                      SecretSharingSchemeProvider lsssInstanceProvider) {
        this.lsssInstanceProvider = lsssInstanceProvider;
        this.field = field;
        if (policy instanceof PolicyFact) {
            //All methods of this lsss assume the root node of the policy is a ThresholdPolicy,
            //therefore a simple ThresholdPolicy with threshold 1 and the PolicyFact as singe child is constructed
            policy = new ThresholdPolicy(1, policy);
        }
        this.rootThresholdPolicy = policy;
        this.secretSharingTree = (InnerSecretSharingNode) createTree(policy);
    }

    public ThresholdTreeSecretSharing(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        this.secretSharingTree = (InnerSecretSharingNode) createTree(this.rootThresholdPolicy);
    }

    /**
     * Transforms a given {@link Policy} to a tree of {@link SecretSharingTreeNode}.
     * <p>
     * Each {@link ThresholdPolicy} is transformed to a {@link InnerSecretSharingNode} while each {@link PolicyFact}
     * is transformed to a {@link LeafSecretSharingNode}.
     *
     * @param policy {@link Policy} to construct a tree of {@link SecretSharingTreeNode} for
     * @return the root node of a tree of {@link SecretSharingTreeNode} represented by the given {@link Policy}
     * @throws IllegalArgumentException if the given {@link Policy} is neither a {@link ThresholdPolicy} nor a
     *                                  {@link PolicyFact}
     */
    private SecretSharingTreeNode createTree(Policy policy) {
        if (policy instanceof PolicyFact) {
            int nextIndex = shareReceiverMap.size() + 1;
            shareReceiverMap.put(nextIndex, policy);
            return new LeafSecretSharingNode(policy);
        }

        if (policy instanceof ThresholdPolicy) {
            ThresholdPolicy thresholdPolicy = (ThresholdPolicy) policy;
            List<SecretSharingTreeNode> children = new ArrayList<>(thresholdPolicy.getChildren().size());
            for (Policy child : thresholdPolicy.getChildren()) {
                children.add(createTree(child));
            }

            int numberOfShares = children.stream().mapToInt(SecretSharingTreeNode::getNumberOfShares).sum();

            return new InnerSecretSharingNode(children, numberOfShares,
                    thresholdPolicy, lsssInstanceProvider.createLSSSInstance(thresholdPolicy, field));
        }

        throw new IllegalArgumentException(policy.getClass().getName() + " is not a supported policy type");
    }

    @Override
    public Map<Integer, Zp.ZpElement> getShares(Zp.ZpElement secret) throws WrongAccessStructureException {
        Map<Integer, Zp.ZpElement> shares = new HashMap<>(secretSharingTree.getNumberOfShares());
        collectShares(secretSharingTree, secret, shares);
        return shares;
    }

    /**
     * Recursively walks the given tree and fills the given map of shares.
     * For each inner node the corresponding lsss is used to generate the inner secrets for its immediate children.
     * Once a leaf is found, a new index is chosen and the given secret is stored in the currentShares map.
     *
     * @param treeNode      root node of the tree to share the secret among
     * @param secret        the secret to share
     * @param currentShares map of shares to fill
     */
    private void collectShares(SecretSharingTreeNode treeNode, Zp.ZpElement secret, Map<Integer,
            Zp.ZpElement> currentShares) {
        if (treeNode instanceof InnerSecretSharingNode) {
            InnerSecretSharingNode innerNode = (InnerSecretSharingNode) treeNode;
            Map<Integer, Zp.ZpElement> shares = innerNode.getLsss().getShares(secret);
            for (int i = 1; i <= innerNode.getNumberOfChildren(); i++) {
                collectShares(innerNode.getChildren().get(i - 1), shares.get(i), currentShares);
            }
        } else if (treeNode instanceof LeafSecretSharingNode) {
            int index = currentShares.size() + 1;
            currentShares.put(index, secret);
        } else {
            throw new IllegalArgumentException(treeNode.getClass().getName() +
                    " is not a supported SecretSharingTreeNode type");
        }
    }

    @Override
    public Map<Integer, Zp.ZpElement> getSolvingVector(Set<? extends Policy> setOfShareReceivers) throws
            NoSatisfyingSet, WrongAccessStructureException {
        Set<SecretSharingTreeNode> setOfQualifiedNodes = new HashSet<>();
        Set<Integer> setOfShareReceiverIds = getSharesOfReceivers(setOfShareReceivers);
        if (!isQualifiedAndFindQualifiedNodes(setOfShareReceiverIds, setOfQualifiedNodes)) {
            throw new NoSatisfyingSet();
        }
        Map<Integer, Zp.ZpElement> childSolvingVector = new HashMap<>(setOfShareReceivers.size());
        collectSolvingVector(secretSharingTree, childSolvingVector, setOfShareReceiverIds, setOfQualifiedNodes,
                field.getOneElement(), 0);
        return childSolvingVector;
    }

    /**
     * Collects the solving vector for the shares (leaves) of the secret sharing tree.
     * The factor corresponding to a share is determined by multiplying all factors determined by the inner
     * {@link LinearSecretSharing} on the path to the associated leaf.
     *
     * <p>
     * For each inner node of the tree {@link LinearSecretSharing#getSolvingVector} is called for its qualified
     * children.
     * The resulting factors are multiplied with the given factor of the current call and passed down to the next
     * recursion.
     * <p>
     * Each leaf found results in the factor of the current call set as part of the solving vector for the
     * corresponding
     * share.
     * <p/>
     *
     * @param node                  (sub-)tree of {@link SecretSharingTreeNode} to determine the solving vectors for
     * @param solvingVector         map (i, a_i) for all shares i = 1,...,n present in the setOfShareReceiverIds
     * @param setOfShareReceiverIds shareReceiver to include in the solving vector
     * @param setOfQualifiedNodes   all nodes which are qualified with respect to the given set of shareReceiver
     * @param factor                factor for the shares determined on the current path on the tree
     * @param shareIdOffset         number of shares already visited
     */
    private void collectSolvingVector(SecretSharingTreeNode node, Map<Integer, Zp.ZpElement> solvingVector,
                                      Set<Integer> setOfShareReceiverIds,
                                      Set<SecretSharingTreeNode> setOfQualifiedNodes,
                                      Zp.ZpElement factor, int shareIdOffset) {

        if (node instanceof LeafSecretSharingNode) {
            int possibleShareId = shareIdOffset + 1;
            if (setOfShareReceiverIds.contains(possibleShareId)) {
                solvingVector.put(possibleShareId, factor);
            }
        } else if (node instanceof InnerSecretSharingNode) {
            InnerSecretSharingNode innerNode = (InnerSecretSharingNode) node;
            List<SecretSharingTreeNode> innerChildren = innerNode.getChildren();

            Set<Policy> qualifiedChildren = setOfQualifiedNodes.stream()
                    .filter(innerChildren::contains)
                    .map(SecretSharingTreeNode::getPolicy)
                    .collect(Collectors.toSet());
            Map<Integer, Zp.ZpElement> childSV = innerNode.getLsss().getSolvingVector(qualifiedChildren);

            for (int i = 1; i <= innerChildren.size(); i++) {
                SecretSharingTreeNode innerChild = innerChildren.get(i - 1);
                if (childSV.containsKey(i)) {
                    collectSolvingVector(innerChild, solvingVector, setOfShareReceiverIds, setOfQualifiedNodes,
                            factor.mul(childSV.get(i)), shareIdOffset);
                }
                shareIdOffset += innerChild.getNumberOfShares();
            }

        } else {
            throw new IllegalArgumentException(node.getClass().getName() +
                    " is not a supported SecretSharingTreeNode type");
        }
    }

    /**
     * Recursively parses the given tree node to collect the shares corresponding to the children of the given node.
     * <p>
     * For each child of the given node act depending on it type:
     * <ul>
     * <li>{@link InnerSecretSharingNode}: call method recursively for this node,
     * reconstruct the node's secret with the collected shares and add the share to the result</li>
     * <li>{@link LeafSecretSharingNode}: find the correct share ids for the corresponding {@link Policy}
     * from the given set of shares based on the offset and add them to the result </li>
     * </ul>
     *
     * </p>
     *
     * @param root          root node of the secret-sharing-tree to parse
     * @param shares        qualified set of shares (fulfilled leafs of the tree)
     * @param shareIdOffset offset to be considered to map the actual share id to the child id of the root
     * @return qualified set of shares to reconstruct the root node's secret
     */
    private Map<Integer, Zp.ZpElement> collectChildShares(InnerSecretSharingNode root, Map<Integer, Zp.ZpElement>
            shares, int shareIdOffset) {
        Map<Integer, Zp.ZpElement> childShares = new HashMap<>();

        int offset = shareIdOffset;
        List<SecretSharingTreeNode> children = root.getChildren();
        for (int i = 0; i < children.size(); i++) {
            SecretSharingTreeNode node = children.get(i);
            if (node instanceof LeafSecretSharingNode) {
                //The current leaf node can only be associated to a share with id 1
                //larger then the previously seen shares (indicated by the offset)
                int possibleShareId = offset + 1;
                if (shares.containsKey(possibleShareId)) {
                    //Depending on the children visited before, the sharedId needs to be offset depending on the
                    // previously number of incorporated shares.
                    //Otherwise the index of leaf nodes would be skewed by their sibling inner nodes
                    int shareIdCorrection = 0;
                    for (int j = 0; j < i; j++) {
                        SecretSharingTreeNode sibling = children.get(j);
                        shareIdCorrection += sibling.getNumberOfShares() - 1;
                    }

                    childShares.put(possibleShareId - shareIdCorrection, shares.get(possibleShareId));
                }

                offset++;

            } else if (node instanceof InnerSecretSharingNode) {
                InnerSecretSharingNode innerNode = (InnerSecretSharingNode) node;
                try {
                    Zp.ZpElement innerSecret = reconstructInnerSecret(shares, offset, innerNode);
                    childShares.put(shareIdOffset + i + 1, innerSecret);
                } catch (NoSatisfyingSet noSatisfyingSet) {
                    //in case an inner node can not be reconstructed, it can be skipped
                    //these nodes are not part of the qualified set for the given root node
                }

                offset += innerNode.getNumberOfShares();
            } else {
                throw new IllegalArgumentException(root.getClass().getName() +
                        " is not a supported SecretSharingTreeNode type");
            }
        }

        return childShares;
    }

    @Override
    public Map<Integer, Policy> getShareReceiverMap() {
        return shareReceiverMap;
    }

    @Override
    public boolean isQualified(Set<? extends Policy> setOfShareReceivers) throws WrongAccessStructureException {
        return isQualifiedAndFindQualifiedNodes(getSharesOfReceivers(setOfShareReceivers), new HashSet<>());
    }

    /**
     * /**
     * Checks whether or not the set of shareReceivers will be able to recreate the secret by pooling their shares {s_i
     * | getShareReceiver(i) \in setOfShareReceivers}
     *
     * @param setOfShareReceivers the set to test.
     * @param setOfQualifiedNodes set to fill with the qualified nodes of the tree
     * @return true if {s_i | getShareReceiver(i) \in setOfShareReceivers} suffices to recreate a shared secret.
     */
    private boolean isQualifiedAndFindQualifiedNodes(Set<Integer> setOfShareReceivers,
                                                     Set<SecretSharingTreeNode> setOfQualifiedNodes) {
        findQualifiedNodes(secretSharingTree, setOfShareReceivers, 0, setOfQualifiedNodes);

        Set<Integer> qualifiedChildren = collectChildIds(secretSharingTree, setOfQualifiedNodes);

        return secretSharingTree.getLsss().isQualified(qualifiedChildren);
    }

    @Override
    public Zp getSharedRing() {
        return field;
    }

    @Override
    public Map<Integer, Zp.ZpElement> completeShares(Zp.ZpElement secret, Map<Integer, Zp.ZpElement> partialShares)
            throws IllegalArgumentException {
        Set<SecretSharingTreeNode> setOfQualifiedNodes = new HashSet<>();
        findQualifiedNodes(secretSharingTree, partialShares.keySet(), 0, setOfQualifiedNodes);

        Map<Integer, Zp.ZpElement> completedShares = new HashMap<>(partialShares);
        completeSharesForChildren(secretSharingTree, secret, completedShares, 0, setOfQualifiedNodes);
        return completedShares;
    }

    /**
     * Recursively parses the given tree node to collect the set of qualified nodes in the tree.
     * The tree nodes found to be qualified are stored in the given set.
     *
     * <p>
     * For each child of the given node act depending on it type:
     * <ul>
     * <li>{@link InnerSecretSharingNode}: call method recursively for this node and
     * select the qualified nodes corresponding to its own children and check.
     * Add this node to the result set iff the set of qualified children are qualified for this node's lsss</li>
     * <li>{@link LeafSecretSharingNode}: find the correct share ids for the corresponding {@link Policy}
     * from the given set of shares based and add them to the result if the id is present in the shareReceiver set</li>
     * </ul>
     *
     * </p>
     *
     * @param root           root node of the secret-sharing-tree to parse
     * @param shareReceivers ids of the shares to use for the qualification check
     * @param shareIdOffset  offset to be considered to map the actual share id to the child id of the root
     * @param qualifiedNodes resulting set to be filled with the nodes which lsss is qualified for the given set of
     *                       shares
     */
    private void findQualifiedNodes(InnerSecretSharingNode root,
                                    Set<Integer> shareReceivers, int shareIdOffset,
                                    Set<SecretSharingTreeNode> qualifiedNodes) {
        List<SecretSharingTreeNode> children = root.getChildren();
        for (SecretSharingTreeNode node : children) {
            if (node instanceof LeafSecretSharingNode) {
                //The current leaf node can only be associated to a share with id 1
                //larger then the previously seen shares (indicated by the offset)
                int possibleShareId = shareIdOffset + 1;
                if (shareReceivers.contains(possibleShareId)) {
                    qualifiedNodes.add(node);
                }
                shareIdOffset++;
            } else if (node instanceof InnerSecretSharingNode) {
                InnerSecretSharingNode innerInnerNode = (InnerSecretSharingNode) node;
                findQualifiedNodes(innerInnerNode, shareReceivers, shareIdOffset, qualifiedNodes);

                shareIdOffset += innerInnerNode.getNumberOfShares();

                Set<Integer> qualifiedChildren = collectChildIds(innerInnerNode, qualifiedNodes);

                if (innerInnerNode.getLsss().isQualified(qualifiedChildren)) {
                    qualifiedNodes.add(node);
                }
            } else {
                throw new IllegalArgumentException(root.getClass().getName() +
                        " is not a supported SecretSharingTreeNode type");
            }
        }
    }

    /**
     * @param parent node to collect their children's ids for
     * @param nodes  Nodes to collect the children from
     * @return ids of all children of the given parent which are present in the given set of nodes
     */
    private Set<Integer> collectChildIds(InnerSecretSharingNode parent, Set<SecretSharingTreeNode>
            nodes) {
        return nodes.stream()
                .filter(parent.getChildren()::contains)
                .map(child -> parent.getChildren().indexOf(child) + 1)
                .collect(Collectors.toSet());
    }

    /**
     * Completes the given incomplete map of shares for all unqualified subtrees of the given root.
     * <p>
     * <ul>
     * <li>For all qualified children: Collect (leaf) or reconstruct (inner node) its share</li>
     * <li>Complete the set of shares</li>
     * <li>For each unqualified child:
     * <ul>
     * <li>if leaf: add newly chosen share to result set</li>
     * <li>if inner node: call completeSharesForChildren recursively with the newly chosen share as secret</li>
     * </ul>
     * </li>
     * </ul>
     *
     * </p>
     *
     * @param root                root node of the subtree to complete
     * @param secret              secret to reconstruct with the completed shares
     * @param completedShares     resulting complete set of shares, initially consisting of the partial set of shares
     * @param shareIdOffset       offset to be considered to map the actual share id to the child id of the root
     * @param setOfQualifiedNodes all nodes in the tree, which are qualified with respect to the partial set of shares
     */
    private void completeSharesForChildren(InnerSecretSharingNode root, Zp.ZpElement secret,
                                           Map<Integer, Zp.ZpElement> completedShares, int shareIdOffset,
                                           Set<SecretSharingTreeNode> setOfQualifiedNodes) {
        Set<Integer> qualifiedChildren = collectChildIds(root, setOfQualifiedNodes);

        //Collect all shares of the qualified children
        //In case of leaf get share from given set of completed shares
        //In case of an inner node use reconstruction mechanism
        Map<Integer, Zp.ZpElement> availableShares = new HashMap<>();
        int offset = shareIdOffset;
        List<SecretSharingTreeNode> children = root.getChildren();
        for (int i = 0; i < children.size(); i++) {
            SecretSharingTreeNode node = children.get(i);

            if (node instanceof LeafSecretSharingNode) {
                if (qualifiedChildren.contains(i + 1)) {
                    //The current leaf node can only be associated to a share with id 1
                    //larger then the previously seen shares (indicated by the offset)
                    int possibleShareId = offset + 1;
                    if (!completedShares.containsKey(possibleShareId)) {
                        throw new WrongAccessStructureException("A leaf is marked as qualified but its share is not " +
                                "present");
                    }
                    availableShares.put(i + 1, completedShares.get(possibleShareId));
                }
                offset++;
            } else if (node instanceof InnerSecretSharingNode) {
                InnerSecretSharingNode innerNode = (InnerSecretSharingNode) node;
                if (qualifiedChildren.contains(i + 1)) {
                    Zp.ZpElement innerSecret = reconstructInnerSecret(completedShares, offset,
                            innerNode);
                    availableShares.put(i + 1, innerSecret);
                }
                offset += innerNode.getNumberOfShares();
            } else {
                throw new IllegalArgumentException(root.getClass().getName() +
                        " is not a supported SecretSharingTreeNode type");
            }
        }

        availableShares = root.getLsss().completeShares(secret, availableShares);

        offset = shareIdOffset;
        for (int i = 0; i < children.size(); i++) {
            SecretSharingTreeNode node = children.get(i);
            if (node instanceof LeafSecretSharingNode) {
                if (!qualifiedChildren.contains(i + 1)) {
                    //The current leaf node can only be associated to a share with id 1
                    //larger then the previously seen shares (indicated by the offset)
                    int possibleShareId = offset + 1;
                    if (completedShares.containsKey(possibleShareId)) {
                        throw new WrongAccessStructureException("A leaf is marked as not qualified but its share is " +
                                "present");
                    }
                    completedShares.put(possibleShareId, availableShares.get(i + 1));
                }
                offset++;
            } else if (node instanceof InnerSecretSharingNode) {
                InnerSecretSharingNode innerNode = (InnerSecretSharingNode) node;

                Zp.ZpElement partialSecret = availableShares.get(i + 1);

                completeSharesForChildren(innerNode, partialSecret, completedShares, offset, setOfQualifiedNodes);

                offset += innerNode.getNumberOfShares();

            } else {
                throw new IllegalArgumentException(root.getClass().getName() +
                        " is not a supported SecretSharingTreeNode type");
            }
        }

    }

    /**
     * Reconstructs the secret of the given inner node based on the set of supplied shares.
     *
     * @param shares        shares used to reconstruct the secret
     * @param shareIdOffset offset to be considered to map the actual share id to the child id of the inner node
     * @param innerNode     node which secret shall be reconstructed
     * @return the inner nodes secret
     * @throws NoSatisfyingSet if the given shares do not suffice to reconstruct the secret
     */
    private Zp.ZpElement reconstructInnerSecret(Map<Integer, Zp.ZpElement> shares, int shareIdOffset,
                                                InnerSecretSharingNode innerNode) {
        Map<Integer, Zp.ZpElement> childInnerNodeShares = collectChildShares(innerNode, shares,
                shareIdOffset);

        //Apply the index shift based on the current offset to map the actual share id to the
        //id used in the internal lsss
        childInnerNodeShares = childInnerNodeShares.entrySet().stream()
                .collect(Collectors.toMap(
                        entry -> entry.getKey() - shareIdOffset,
                        Map.Entry::getValue
                ));

        if (!innerNode.getLsss().isQualified(childInnerNodeShares.keySet())) {
            throw new NoSatisfyingSet();
        }
        return innerNode.getLsss().reconstruct(childInnerNodeShares);
    }

    @Override
    public boolean checkShareConsistency(Zp.ZpElement secret, Map<Integer, Zp.ZpElement> shares) {
        if (shares.size() != getShareReceiverMap().size()) {
            throw new IllegalArgumentException("The given set of shares is not a complete set!");
        }
        return checkShareConsistencyForChildren(secretSharingTree, secret, shares, 0);
    }

    private boolean checkShareConsistencyForChildren(InnerSecretSharingNode root, Zp.ZpElement secret,
                                                     Map<Integer, Zp.ZpElement> shares, int shareIdOffset) {
        Map<Integer, Zp.ZpElement> childShares = new HashMap<>();

        int offset = shareIdOffset;
        List<SecretSharingTreeNode> children = root.getChildren();
        for (int i = 0; i < children.size(); i++) {
            SecretSharingTreeNode node = children.get(i);
            if (node instanceof LeafSecretSharingNode) {
                //The current leaf node can only be associated to a share with id 1
                //larger then the previously seen shares (indicated by the offset)
                int actualShareId = offset + 1;
                childShares.put(i + 1, shares.get(actualShareId));
                offset++;

            } else if (node instanceof InnerSecretSharingNode) {
                InnerSecretSharingNode innerNode = (InnerSecretSharingNode) node;

                Map<Integer, Zp.ZpElement> childInnerNodeShares = collectChildShares(innerNode, shares,
                        offset);

                int currentOffset = offset;
                //Apply the index shift based on the current offset to map the actual share id to the
                //id used in the internal lsss
                childInnerNodeShares = childInnerNodeShares.entrySet().stream()
                        .collect(Collectors.toMap(
                                entry -> entry.getKey() - currentOffset,
                                Map.Entry::getValue
                        ));
                Zp.ZpElement innerSecret = innerNode.getLsss().reconstruct(childInnerNodeShares);
                childShares.put(i + 1, innerSecret);
                if (!checkShareConsistencyForChildren(innerNode, innerSecret, shares, offset)) {
                    return false;
                }

                offset += innerNode.getNumberOfShares();
            } else {
                throw new IllegalArgumentException(root.getClass().getName() +
                        " is not a supported SecretSharingTreeNode type");
            }
        }
        return root.getLsss().checkShareConsistency(secret, childShares);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ThresholdTreeSecretSharing that = (ThresholdTreeSecretSharing) o;
        boolean equalsLsss = Objects.equals(lsssInstanceProvider, that.lsssInstanceProvider);

        boolean equalsField = Objects.equals(field, that.field);
        boolean equalsPolicy = Objects.equals(rootThresholdPolicy, that.rootThresholdPolicy);
        boolean equalsTree = Objects.equals(secretSharingTree, that.secretSharingTree);
        boolean equalsMap = Objects.equals(shareReceiverMap, that.shareReceiverMap);


        return Objects.equals(lsssInstanceProvider, that.lsssInstanceProvider) &&
                Objects.equals(field, that.field) &&
                Objects.equals(rootThresholdPolicy, that.rootThresholdPolicy) &&
                Objects.equals(secretSharingTree, that.secretSharingTree) &&
                Objects.equals(shareReceiverMap, that.shareReceiverMap);
    }

    @Override
    public int hashCode() {
        return Objects.hash(lsssInstanceProvider, field, rootThresholdPolicy, secretSharingTree, shareReceiverMap);
    }
}
