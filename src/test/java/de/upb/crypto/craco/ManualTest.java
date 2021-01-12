package de.upb.crypto.craco;

import de.upb.crypto.craco.common.interfaces.EncryptionScheme;
import org.reflections.Reflections;

import java.lang.reflect.Modifier;
import java.util.Set;

public class ManualTest {

    public static void main(String[] args) {
        Reflections reflectionCraco = new Reflections("de.upb.crypto.craco");
        Set<Class<? extends EncryptionScheme>> schemeClasses = reflectionCraco.getSubTypesOf(EncryptionScheme.class);
        for (Class<? extends EncryptionScheme> clazz : schemeClasses) {
            if (!clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers())) {
                System.out.println(clazz);
            }
        }
    }
}
