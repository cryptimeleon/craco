package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.SymmetricKey;
import de.upb.crypto.craco.interfaces.pe.*;
import de.upb.crypto.math.serialization.Representation;

/**
 * A KEM that is implemented by the composition of a {@link PredicateKEM} providing {@link KeyMaterial} and a
 * {@link KeyDerivationFunction} that derives a {@link SymmetricKey} from the {@link KeyMaterial} produced by the KEM.
 * <p>
 * This should be used in combination with an symmetric encryption scheme to implement the standard hybrid encryption
 * technique.
 *
 * @author Denis Diemert
 */
public class SymmetricKeyPredicateKEM extends SymmetricKeyKEM implements PredicateKEM<SymmetricKey> {

    public SymmetricKeyPredicateKEM(PredicateKEM<? extends KeyMaterial> kem,
                                    KeyDerivationFunction<? extends SymmetricKey> kdf) {
        super(kem, kdf);
    }

    public SymmetricKeyPredicateKEM(Representation repr) {
        super(repr);
    }

    @Override
    public MasterSecret getMasterSecret(Representation repr) {
        return ((PredicateKEM<? extends KeyMaterial>) kem).getMasterSecret(repr);
    }

    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        return ((PredicateKEM<? extends KeyMaterial>) kem).generateDecryptionKey(msk, kind);
    }

    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        return ((PredicateKEM<? extends KeyMaterial>) kem).generateEncryptionKey(cind);
    }

    @Override
    public Predicate getPredicate() {
        return ((PredicateKEM<? extends KeyMaterial>) kem).getPredicate();
    }
}
