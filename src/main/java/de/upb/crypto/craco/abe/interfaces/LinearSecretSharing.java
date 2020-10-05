package de.upb.crypto.craco.abe.interfaces;

import de.upb.crypto.craco.abe.accessStructure.exception.NoSatisfyingSet;
import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A (linear) secret sharing scheme allows sharing a secret,
 * which results in a set of shares. Each share belongs to some shareReceiver (one shareReceiver may get multiple
 * shares).
 * The scheme defines which sets of shareReceivers are able to pool their shares in order to recreate the secret.
 * <p>
 * The API works as follows:
 * <ul>
 * <li> The participants of the scheme are called shareReceivers (which may be actual parties in a protocol or
 * ABE attributes, or any other entities that you may want to distribute a secret over).</li>
 * <li> The scheme is instantiated with a sharing policy that determines which subsets of shareReceivers
 * can recreate a shared secret (such subsets are called "qualified").</li>
 * <li> getShares(secret) computes a randomized set of "shares" {(i, s_i)}, where i = 1,...,n.</li>
 * <li> getShareReceiver(i) determines which shareReceiver the share s_i belongs to (one shareReceiver may get multiple
 * shares).</li>
 * <li> getSolvingVector(S) for a subset S of shareReceivers, where isQualified(S) == true, determines how to recreate a
 * secret using the shares of S.
 * More specifically, it computes coefficients a_i such that \sum a_i * s_i = secret (such that for each i in that sum,
 * getShareReceiver(i)\in S).
 * (Hence the name LINEAR secret sharing).</li>
 * </ul>
 * The security guarantee is that for any set S of shareReceivers that is NOT qualified, the
 * corresponding set of shares {s_i | getShareReceiver(i) \in S} does NOT suffice to recreate the secret.
 * (Some implementations will ensure that these shares are completely independent of the secret).
 * </p>
 *
 * @author pschleiter, refactoring: Fabian Eidens, javadoc: Jan
 */
public interface LinearSecretSharing<ShareReceiverType> {

    /**
     * Randomly generates shares s_i for the given secret. Use getShareReceiver(i) to determine which share belongs to
     * which shareReceiver.
     *
     * @return a vector of shares s_i (as a map i -> s_i).
     */
    Map<Integer, ZpElement> getShares(ZpElement secret) throws WrongAccessStructureException;

    /**
     * Instructs how to reconstruct a shared secret using the shares of a given setOfShareReceivers. More specifically,
     * computes a vector of coefficients a_i such that \sum a_i * s_i = secret for the s_i output by getShares(secret).
     * Only shares s_i with getShareReceiver(i) \in setOfShareReceivers appear in this sum (one can imagine that all
     * other a_i are 0).
     *
     * @return a vector of coefficients a_i (as a map i -> a_i). Contains only i where getShareReceiver(i) \in
     * setOfShareReceivers.
     * @throws NoSatisfyingSet if !isQualified(setOfShareReceivers)
     */
    Map<Integer, ZpElement> getSolvingVector(Set<? extends ShareReceiverType> setOfShareReceivers) throws
            NoSatisfyingSet, WrongAccessStructureException;


    /**
     * Reconstructs the secret using the given shares.
     *
     * @param shares a partial set of shares (i.e. a map containing a (qualified) subset of the entries of
     *               getShares()).
     * @return the reconstructed secret
     * @throws NoSatisfyingSet if the set of share receivers implied by the shares is not qualified
     */
    default ZpElement reconstruct(Map<Integer, ZpElement> shares) throws NoSatisfyingSet,
            WrongAccessStructureException {
        Set<ShareReceiverType> shareReceivers = getShareReceiverMap().entrySet().stream()
                .filter(entry -> shares
                        .containsKey(entry.getKey()))
                .map(Map.Entry::getValue)
                .collect(Collectors.toSet());

        Map<Integer, ZpElement> solvingVector = getSolvingVector(shareReceivers);

        return shares.entrySet().stream() // look at all shares
                .map(e -> e.getValue()
                        .mul(solvingVector.getOrDefault(e.getKey(), getSharedRing().getZeroElement())))
                .reduce(getSharedRing().getZeroElement(), ZpElement::add); // add all of them
    }

    /**
     * Given the index i of a share s_i, determines which shareReceiver that share belongs to.
     *
     * @param i the index of a share
     * @return the shareReceiver that share s_i belongs to.
     */
    default ShareReceiverType getShareReceiver(Integer i) {
        return getShareReceiverMap().get(i);
    }

    /**
     * Returns the map that assigns each index i of a share s_i to its shareReceiver.
     */
    Map<Integer, ShareReceiverType> getShareReceiverMap();

    /**
     * Returns the set of share indices i that belong to the given shareReceiver. (i.e.
     * getShareReceiver^{-1}(shareReceiver)).
     */
    default Set<Integer> getSharesOfReceiver(ShareReceiverType shareReceiver) {
        return getSharesOfReceivers(Collections.singletonList(shareReceiver));
    }

    /**
     * Returns the set of share indices i that belong to any one of the shareReceivers. (i.e.
     * getShareReceiver^{-1}(shareReceivers)).
     */
    default Set<Integer> getSharesOfReceivers(Collection<? extends ShareReceiverType> shareReceivers) {
        return getShareReceiverMap().entrySet().stream()
                .filter(e -> shareReceivers.contains(e.getValue()))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    /**
     * Checks whether or not the set of shareReceivers will be able to recreate the secret by pooling their shares {s_i
     * | getShareReceiver(i) \in setOfShareReceivers}
     *
     * @param setOfShareReceivers the set to test.
     * @return true if {s_i | getShareReceiver(i) \in setOfShareReceivers} suffices to recreate a shared secret.
     */
    boolean isQualified(Set<? extends ShareReceiverType> setOfShareReceivers) throws WrongAccessStructureException;

    /**
     * Checks whether or not the set of shareReceivers will be able to recreate the secret by pooling their shares {s_i
     * | i \in setOfShareReceiversIds}
     *
     * @param setOfShareReceiversIds the set to test.
     * @return true if {s_i | i \in setOfShareReceiversIds} suffices to recreate a shared secret.
     */
    default boolean isQualified(Collection<Integer> setOfShareReceiversIds) throws WrongAccessStructureException {
        Set<? extends ShareReceiverType> setOfShareReceivers = getShareReceiverMap().entrySet().stream()
                .filter(entry -> setOfShareReceiversIds
                        .contains(entry.getKey()))
                .map(Map.Entry::getValue)
                .collect(Collectors.toSet());
        return isQualified(setOfShareReceivers);
    }

    /**
     * Returns the ring over which the secret is being shared
     */
    Zp getSharedRing();

    /**
     * Takes a partial set of shares and completes it to a full set of shares for the given secret. In case of
     * isQualified(S)==true this method will simply recreate the full set of shares.
     *
     * <p>
     * The contract is that the two S in the following are distributed identically:
     * <ul>
     * <li>S = getShares(s)</li>
     * <li>S = completeShares(s, {s_i' | i \in getSharesOfReceivers(X)}) with {s_i'} = getShares(s') and a subset X of
     * shareReceivers.</li>
     * </ul>
     * (that property is called semi-smoothness)
     * </p>
     *
     * @param secret        the desired secret for the completed shares
     * @param partialShares the set of partial shares {s_i | i \in getSharesOfReceivers(X)}
     * @return a complete set of shares distributed like getShares(secret) (if the given partial shares are distributed
     * as in getShares())
     * @throws IllegalArgumentException      if partialShares cannot be completed to secret.
     * @throws UnsupportedOperationException if the scheme does not support completion of shares.
     */
    Map<Integer, ZpElement> completeShares(ZpElement secret, Map<Integer, ZpElement> partialShares) throws
            IllegalArgumentException;

    /**
     * Outputs true if the given (full) set of shares is consistent with the given secret. (i.e. if all qualified
     * subsets of the shares will recreate the given secret)
     */
    boolean checkShareConsistency(ZpElement secret, Map<Integer, ZpElement> shares);
}
