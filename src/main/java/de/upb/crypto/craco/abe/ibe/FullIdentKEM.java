package de.upb.crypto.craco.abe.ibe;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.SymmetricKey;
import de.upb.crypto.craco.kem.AbstractHybridConstructionKEM;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.math.serialization.Representation;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * A KEM that produces AES keys encapsulated via ABE
 *
 * @author Jan
 */
public class FullIdentKEM extends AbstractHybridConstructionKEM {

    private FullIdent scheme;

    private SecureRandom random;

    public FullIdentKEM(FullIdent scheme) {
        super(scheme, new HashBasedKeyDerivationFunction());
        this.scheme = scheme;
        random = new SecureRandom();
    }

    public FullIdentKEM(Representation repr) {
        this(new FullIdent(repr));
    }

    @Override
    protected PlainText generateRandomPlaintext() {
        byte[] toReturn = new byte[scheme.getPublicParameters().getN().intValue()];
        random.nextBytes(toReturn);
        return new ByteArrayImplementation(toReturn);
    }

    @Override
    public Representation getRepresentation() {
        return scheme.getRepresentation();
    }

    public SymmetricKey getKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    protected int getPlaintextMinEntropyInBit() {
        return (int) Math.pow(2, scheme.getPublicParameters().getN().intValue());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((random == null) ? 0 : random.hashCode());
        result = prime * result + ((scheme == null) ? 0 : scheme.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        FullIdentKEM other = (FullIdentKEM) obj;
        return Objects.equals(scheme, other.scheme)
                && ((random == null && other.random == null) || (random != null && other.random != null));
    }
}
