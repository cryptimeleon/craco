package de.upb.crypto.craco.interfaces.abe;

import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.interfaces.pe.Predicate;
import de.upb.crypto.craco.interfaces.policy.Policy;

public class AbePredicate implements Predicate {
    @Override
    public boolean check(KeyIndex kind, CiphertextIndex cind) {
        if (kind instanceof SetOfAttributes && cind instanceof Policy)
            return ((Policy) cind).isFulfilled((SetOfAttributes) kind);
        if (cind instanceof SetOfAttributes && kind instanceof Policy)
            return ((Policy) kind).isFulfilled((SetOfAttributes) cind);
        return false;
    }
}
