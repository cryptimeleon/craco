package de.upb.crypto.craco.interfaces.abe;

import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;

public interface Attribute extends Policy, PolicyFact, UniqueByteRepresentable {

}
