package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.interfaces.pe.Predicate;
import de.upb.crypto.craco.kem.AbstractHybridPredicateKEM;
import de.upb.crypto.craco.kem.HashBasedKeyDerivationFunction;
import de.upb.crypto.math.serialization.Representation;

/**
 * A KEM that produces AES keys encapsulated via ABE
 *
 * @author Jan
 */
public class ABECPWat11SmallKEM extends AbstractHybridPredicateKEM {

    private ABECPWat11Small scheme;

    public ABECPWat11SmallKEM(ABECPWat11Small scheme) {
        super(scheme, new HashBasedKeyDerivationFunction());
        this.scheme = scheme;
    }

    public ABECPWat11SmallKEM(Representation repr) {
        this(new ABECPWat11Small(repr));
    }

    @Override
    protected PlainText generateRandomPlaintext() {
        return new GroupElementPlainText(scheme.getPublicParameters().getGroupGT().getUniformlyRandomElement());
    }

    @Override
    public Representation getRepresentation() {
        return scheme.getRepresentation();
    }

    public ByteArrayImplementation getKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    protected int getPlaintextMinEntropyInBit() {
        return scheme.getPublicParameters().getGroupGT().size().bitLength();
    }

    @Override
    public MasterSecret getMasterSecret(Representation repr) {
        return scheme.getMasterSecret(repr);
    }

    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        return scheme.generateDecryptionKey(msk, kind);
    }

    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        return scheme.generateEncryptionKey(cind);
    }

    @Override
    public Predicate getPredicate() {
        return scheme.getPredicate();
    }

    public ABECPWat11SmallPublicParameters getPublicParameters() {
        return scheme.getPublicParameters();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
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
        ABECPWat11SmallKEM other = (ABECPWat11SmallKEM) obj;
        if (scheme == null) {
            if (other.scheme != null)
                return false;
        } else if (!scheme.equals(other.scheme))
            return false;
        return true;
    }

}
