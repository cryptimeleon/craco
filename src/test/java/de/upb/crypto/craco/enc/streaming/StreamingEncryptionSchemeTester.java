package de.upb.crypto.craco.enc.streaming;

import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.common.interfaces.StreamingEncryptionScheme;
import org.reflections.Reflections;

import java.lang.reflect.Modifier;
import java.util.*;
import java.util.stream.Stream;

public class StreamingEncryptionSchemeTester {

    public static Stream<StreamingEncryptionSchemeTestParam> getParams() {
        // Get all classes that implement EncryptionScheme in Craco
        Reflections reflectionCraco = new Reflections("de.upb.crypto.craco");
        Set<Class<? extends StreamingEncryptionScheme>> schemeClasses =
                reflectionCraco.getSubTypesOf(StreamingEncryptionScheme.class);
        // Get all classes that provide parameters for the encryption scheme tests
        Reflections reflectionParams = new Reflections("de.upb.crypto.craco.enc.streaming.params");
        Set<Class<? extends TestParameterProvider>> paramProviderClasses =
                reflectionParams.getSubTypesOf(TestParameterProvider.class);

        // Fill the list of parameters used in test with the found parameters
        List<StreamingEncryptionSchemeTestParam> paramsToTest = new LinkedList<>();
        for (Class<? extends TestParameterProvider> providerClass : paramProviderClasses) {
            try {
                Object params = providerClass.newInstance().get();
                if (params instanceof Collection<?>) {
                    paramsToTest.addAll((Collection) params);
                } else if (params instanceof StreamingEncryptionSchemeTestParam[]) {
                    paramsToTest.addAll(Arrays.asList((StreamingEncryptionSchemeTestParam[]) params));
                } else if (params instanceof StreamingEncryptionSchemeTestParam) {
                    paramsToTest.add((StreamingEncryptionSchemeTestParam) params);
                } else {
                    System.out.println("Params for " + providerClass + " are not of type " +
                            "StreamingEncryptionSchemeTestParam");
                }
            } catch (InstantiationException | IllegalAccessException e) {
                System.out.println("Not able to instantiate streaming encryption scheme test parameter provider "
                        + providerClass + " because of " + e);
            }
        }
        // ADD YOUR EXTERNAL PARAMETERS (outside of de.upb.crypto.craco.enc.params) HERE (to paramsToTest)

        // Remove all schemes that have parameters provided from the list of classes
        for (StreamingEncryptionSchemeTestParam param : paramsToTest) {
            schemeClasses.remove(param.getScheme().getClass());
        }

        // Classes without provided parameters have empty params that will force an error in the test
        for (Class<? extends StreamingEncryptionScheme> clazz : schemeClasses) {
            if (!clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers())) {
                paramsToTest.add(new StreamingEncryptionSchemeTestParam(clazz));
            }
        }
        return paramsToTest.stream();
    }
}
