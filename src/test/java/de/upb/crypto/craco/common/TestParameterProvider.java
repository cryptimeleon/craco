package de.upb.crypto.craco.common;

/**
 * Common interface for test parameter provider classes.
 * The {@link TestParameterProvider#get()} method should provide an instance of the test parameters that
 * correspond to the type of scheme being tested.
 *
 * @author Raphael Heitjohann
 */
public interface TestParameterProvider {

    Object get();
}