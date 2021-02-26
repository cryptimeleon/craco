package org.cryptimeleon.craco.ser.standalone;

import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.reflections.Reflections;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class StandaloneReprTest {
    protected static HashSet<Class<? extends StandaloneRepresentable>> testedClasses = new HashSet<>();
    private static final Reflections reflection = new Reflections("org.cryptimeleon.craco");

    @ParameterizedTest(name = "''{0}''")
    @ArgumentsSource(SubtestArgumentProvider.class)
    public void testStandaloneRepresentables(StandaloneReprSubTest subtest) {
        testedClasses.addAll(subtest.runTests());
    }

    @Test
    public void testStandaloneRepresentablesWithParameterlessConstructors() {
        testedClasses.addAll(new TestForParameterlessConstructorClasses().runTests());
    }

    public static class SubtestArgumentProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return reflection.getSubTypesOf(StandaloneReprSubTest.class).stream()
                    .filter(clazz -> !clazz.equals(TestForParameterlessConstructorClasses.class))
                    .map(clazz -> {
                        try {
                            return clazz.getDeclaredConstructor().newInstance();
                        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
                            e.printStackTrace();
                            return null;
                        }
                    })
                    .filter(Objects::nonNull)
                    .map(Arguments::of);
        }
    }

    private static class TestForParameterlessConstructorClasses extends StandaloneReprSubTest {
        public void testClassesWithTrivialConstructor() {
            reflection.getSubTypesOf(StandaloneRepresentable.class).stream()
                    .filter(clazz -> Arrays.stream(clazz.getConstructors()).anyMatch(constr -> constr.getParameterCount() == 0))
                    .forEach(clazz -> {
                        try {
                            test(clazz.getConstructor().newInstance());
                        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
                            fail(e);
                        }
                    });
        }
    }

    @AfterAll
    @DisplayName("Checking that every StandaloneRepresentable has been tested.")
    static void checkForUntestedClasses() {
        Set<Class<? extends StandaloneRepresentable>> classesToTest = reflection.getSubTypesOf(StandaloneRepresentable.class);
        classesToTest.removeAll(testedClasses);

        //Remove interfaces and such
        classesToTest.removeIf(c -> c.isInterface() || Modifier.isAbstract(c.getModifiers()) || !c.getPackage().toString().startsWith("package org.cryptimeleon.craco"));

        for (Class<? extends StandaloneRepresentable> notTestedClass : classesToTest) {
            System.err.println(notTestedClass.getName() + " implements StandaloneRepresentable was not tested by StandaloneTest. You need to define a StandaloneSubTest for it.");
        }

        assertTrue(classesToTest.isEmpty(), "Missing StandaloneRepresentation tests for some class(es).");
    }
}
