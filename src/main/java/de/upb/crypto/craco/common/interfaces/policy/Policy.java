package de.upb.crypto.craco.common.interfaces.policy;

import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

import java.util.Collection;

public interface Policy extends StandaloneRepresentable, CiphertextIndex, KeyIndex, UniqueByteRepresentable {
    public boolean isFulfilled(Collection<? extends PolicyFact> facts);
}
