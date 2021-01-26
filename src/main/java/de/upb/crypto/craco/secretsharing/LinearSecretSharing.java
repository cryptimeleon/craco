package de.upb.crypto.craco.secretsharing;

import de.upb.crypto.craco.secretsharing.accessstructure.exception.NoSatisfyingSet;
import de.upb.crypto.craco.secretsharing.accessstructure.exception.WrongAccessStructureException;
import de.upb.crypto.math.structures.rings.zn.Zp;
import de.upb.crypto.math.structures.rings.zn.Zp.ZpElement;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A (linear) secret sharing scheme allows sharing a secret,
 * which results in a set of shares. Each share belongs to some share receiver (one share receiver may get multiple
 * shares).
 * The scheme defines which sets of share receivers are able to pool their shares in order to recreate the secret.
 * <p>
 * The API works as follows:
 * <ul>
 * <li> The participants of the scheme are called share receivers (which may be actual parties in a protocol or
 * ABE attributes, or any other entities that you may want to distribute a secret over).</li>
 * <li> The scheme is instantiated with a sharing policy that determines which subsets of share receivers
 * can recreate a shared secret (such subsets are called "qualified").</li>
 * <li> {@code getShares(secret)} computes a randomized set of "shares" \(\{(i, s_i)\}\), where \(i = 1,...,n\).</li>
 * <li> {@code getShareReceiver(i)} determines which share receiver the share \(s_i\) belongs to (one share receiver may
 * get multiple shares).</li>
 * <li> {@code getSolvingVector(S)} for a subset {@code S} of share receivers, where {@code isQualified(S) == true},
 * determines how to recreate a secret using the shares of {@code S}.
 * More specifically, it computes coefficients \(a_i\) such that \(\sum a_i \cdot s_i = \text{secret}\)
 * (such that for each i in that sum, {@code getShareReceiver(i)} is contained in {@code S}).
 * (Hence the name LINEAR secret sharing).</li>
 * </ul>
 * <p>
 * The security guarantee is that for any set \(S\) of share receivers that is NOT qualified, the
 * corresponding set of shares \(\{s_i \; | \; \text{getShareReceiver}(i) \in S\}\) does NOT suffice to recreate
 * the secret.
 * (Some implementations will ensure that these shares are completely independent of the secret).
 *
 * @param <ShareReceiverType> the type of the entities that the secret shares are distributed to
 *
 * @author pschleiter, refactoring: Fabian Eidens, javadoc: Jan
 */
public interface LinearSecretSharing<ShareReceiverType> {

    /**
     * Randomly generates shares \(s_i\) for the given secret.
     * Use {@code getShareReceiver(i)} to determine which share belongs to which share receiver.
     *
     * @return a vector of shares \(s_i\) (as a map mapping index i to share \(s_i\)).
     */
    Map<Integer, ZpElement> getShares(ZpElement secret) throws WrongAccessStructureException;

    /**
     * Instructs how to reconstruct a shared secret using the shares of a given set of share receivers
     * {@code setOfShareReceivers}.
     * More specifically, computes a vector of coefficients \(a_i\) such that
     * \(\sum a_i \cdot s_i = \text{secret}\) for the \(s_i\) output by {@code getShares(secret)}.
     * Only shares \(s_i\) with {@code getShareReceiver(i)} contained in {@code setOfShareReceivers}
     * appear in this sum  (one can imagine that all other \(a_i\) are 0).
     *
     * @param setOfShareReceivers the set of share receivers to calculate the solving vector for
     * @return a vector of coefficients \(a_i\) (as a map index i to coefficient \(a_i\)).
     * Contains only i where {@code getShareReceiver(i)} is contained in {@code setOfShareReceivers}.
     * @throws NoSatisfyingSet if the given set of share receivers cannot reconstruct the secret,
     * i.e. {@code isQualified(setOfShareReceivers) == false}
     */
    Map<Integer, ZpElement> getSolvingVector(Set<? extends ShareReceiverType> setOfShareReceivers) throws
            NoSatisfyingSet, WrongAccessStructureException;


    /**
     * Reconstructs the secret using the given shares.
     *
     * @param shares a partial set of shares (i.e. a map containing a (qualified) subset of the entries of
     *               {@code getShares()}).
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
     * Given the index i of a share \(s_i\), determines which share receiver that share belongs to.
     *
     * @param i the index of a share
     * @return the shareReceiver that share \(s_i\) belongs to
     */
    default ShareReceiverType getShareReceiver(Integer i) {
        return getShareReceiverMap().get(i);
    }

    /**
     * Returns the map that assigns each index i of a share \(s_i\) to its share receiver.
     */
    Map<Integer, ShareReceiverType> getShareReceiverMap();

    /**
     * Returns the set of share indices i that belong to the given share receiver. Essentially computes the
     * inverse of {@link #getShareReceiver(Integer)}.
     */
    default Set<Integer> getSharesOfReceiver(ShareReceiverType shareReceiver) {
        return getSharesOfReceivers(Collections.singletonList(shareReceiver));
    }

    /**
     * Returns the set of share indices i that belong to any of the given share receivers.
     * <p>
     * Essentially {@link #getSharesOfReceiver(Object)}, but applied to multiple share receivers and with the
     * results combined into a single set via union.
     */
    default Set<Integer> getSharesOfReceivers(Collection<? extends ShareReceiverType> shareReceivers) {
        return getShareReceiverMap().entrySet().stream()
                .filter(e -> shareReceivers.contains(e.getValue()))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
    }

    /**
     * Checks whether or not the given set of share receivers will be able to recreate the secret
     * by pooling their shares \(\{s_i \; | \; \text{getShareReceiver}(i) \in \text{setOfShareReceivers}\}\).
     *
     * @param setOfShareReceivers the set of share receivers to check
     * @return true if the shares of the given share receivers suffice to recreate a shared secret
     */
    boolean isQualified(Set<? extends ShareReceiverType> setOfShareReceivers) throws WrongAccessStructureException;

    /**
     * Checks whether or not the set of share receivers given by their identifying ids will be able to recreate
     * the secret by pooling their shares \(\{s_i \; | \; i \in \text{setOfShareReceiversIds}\}\).
     *
     * @param setOfShareReceiversIds the set of share receiver ids to check
     * @return true if the shares of the given share receivers suffice to recreate a shared secret
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
     * Returns the ring over which the secret is being shared.
     */
    Zp getSharedRing();

    /**
     * Takes a partial set of shares and completes it to a full set of shares for the given secret. In case of
     * {@code isQualified(S) == true} this method will simply recreate the full set of shares.
     * <p>
     * The contract is that the two S in the following are distributed identically:
     * <ul>
     * <li>\(S = \text{getShares}(s)\)</li>
     * <li>\(S = \text{completeShares}(s, \{s_i' \; | \; i \in \text{getSharesOfReceivers(X)}\})\) with
     * \(\{s_i'\} = \text{getShares}(s')\) and a subset \(X\) of share receivers.</li>
     * </ul>
     * (that property is called semi-smoothness)

     * @param secret        the desired secret for the completed shares
     * @param partialShares the set of partial shares \(\{s_i \; | \; i \in \text{getSharesOfReceivers}(X)\}\)
     * @return a complete set of shares distributed like {@code getShares(secret)}
     *         (if the given partial shares are distributed as in {@code getShares()})
     * @throws IllegalArgumentException      if {@code partialShares} cannot be completed to secret
     * @throws UnsupportedOperationException if the scheme does not support completion of shares
     */
    Map<Integer, ZpElement> completeShares(ZpElement secret, Map<Integer, ZpElement> partialShares) throws
            IllegalArgumentException;

    /**
     * Outputs true if the given (full) set of shares is consistent with the given secret, meaning that all qualified
     * subsets of the shares will recreate the given secret.
     */
    boolean checkShareConsistency(ZpElement secret, Map<Integer, ZpElement> shares);
}
