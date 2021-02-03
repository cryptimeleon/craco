package de.upb.crypto.craco.common.attributes;

import de.upb.crypto.craco.common.policies.Policy;
import de.upb.crypto.craco.common.policies.PolicyFact;
import de.upb.crypto.math.hash.UniqueByteRepresentable;

public interface Attribute extends Policy, PolicyFact, UniqueByteRepresentable {

}
