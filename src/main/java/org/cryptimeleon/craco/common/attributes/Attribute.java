package org.cryptimeleon.craco.common.attributes;

import org.cryptimeleon.craco.common.policies.Policy;
import org.cryptimeleon.craco.common.policies.PolicyFact;
import org.cryptimeleon.math.hash.UniqueByteRepresentable;

public interface Attribute extends Policy, PolicyFact, UniqueByteRepresentable {

}
