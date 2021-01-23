package de.upb.crypto.craco.kdf.lhl;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.kem.KeyDerivationFunction;
import de.upb.crypto.craco.kem.KeyMaterial;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * An instance of {@link LHLFamily}.
 *
 * @see LHLFamily
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
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
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

        return Objects.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return hash != null ? hash.hashCode() : 0;
    }
}
