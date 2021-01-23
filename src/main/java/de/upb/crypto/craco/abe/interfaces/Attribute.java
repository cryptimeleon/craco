package de.upb.crypto.craco.abe.interfaces;

import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.common.interfaces.policy.PolicyFact;
import de.upb.crypto.math.hash.UniqueByteRepresentable;

public interface Attribute extends Policy, PolicyFact, UniqueByteRepresentable {

}
