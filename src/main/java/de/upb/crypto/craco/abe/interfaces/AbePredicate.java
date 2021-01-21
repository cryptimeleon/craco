package de.upb.crypto.craco.abe.interfaces;

import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.pe.Predicate;
import de.upb.crypto.craco.common.interfaces.policy.Policy;

/**
 * A predicate that can check whether a given {@link Policy} is fulfilled by a {@link SetOfAttributes}.
 */
public class AbePredicate implements Predicate {

    /**
     * Returns result of evaluating the predicate.
     * @return true if the predicate is fulfilled, else false
     */
    @Override
    public boolean check(KeyIndex kind, CiphertextIndex cind) {
        if (kind instanceof SetOfAttributes && cind instanceof Policy)
            return ((Policy) cind).isFulfilled((SetOfAttributes) kind);
        if (cind instanceof SetOfAttributes && kind instanceof Policy)
            return ((Policy) kind).isFulfilled((SetOfAttributes) cind);
        return false;
    }
}
