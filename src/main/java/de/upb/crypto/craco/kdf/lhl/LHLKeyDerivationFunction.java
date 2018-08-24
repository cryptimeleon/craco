package de.upb.crypto.craco.kdf.lhl;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.kem.KeyDerivationFunction;
import de.upb.crypto.craco.kem.KeyMaterial;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

/**
 * An instance of {@link LHLFamily}. For more information see javadoc there.
 *
 * @author Mirko Jürgens, javadoc & refactoring: Denis Diemert
 */
public class LHLKeyDerivationFunction implements KeyDerivationFunction<ByteArrayImplementation> {

    @Represented
    private UniversalHashFunction hash;

    // Intentionally package private, since only family should use this constructor
    LHLKeyDerivationFunction(UniversalHashFunction hash) {
        this.hash = hash;
    }

    public LHLKeyDerivationFunction(Representation repr) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(repr, this);
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public ByteArrayImplementation deriveKey(KeyMaterial material) {
        return new ByteArrayImplementation(hash.hash(material));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        LHLKeyDerivationFunction that = (LHLKeyDerivationFunction) o;

        return hash != null ? hash.equals(that.hash) : that.hash == null;
    }

    @Override
    public int hashCode() {
        return hash != null ? hash.hashCode() : 0;
    }
}
