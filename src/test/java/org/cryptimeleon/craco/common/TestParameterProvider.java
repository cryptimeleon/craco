package org.cryptimeleon.craco.common;

/**
 * Common interface for test parameter provider classes.
 * The {@link TestParameterProvider#get()} method should provide an instance (or a list or array of instances)
 * of the test parameters that correspond to the type of scheme being tested.
 */
public interface TestParameterProvider {

    /**
     * Returns an instance (or a list or array of instances) of the corresponding test parameters.
     */
    Object get();
}