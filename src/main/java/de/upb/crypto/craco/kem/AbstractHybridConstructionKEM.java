package de.upb.crypto.craco.kem;

import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.craco.enc.*;
import de.upb.crypto.math.hash.UniqueByteRepresentable;
import de.upb.crypto.math.serialization.Representation;

/**
 * A KEM that implements {@link #encaps(EncryptionKey)} by generating a random key and encrypting it afterwards
 * with some encryption scheme.
 * <p>
 * Implementations of this abstract class need to define how to generate random plaintexts for the encryption scheme
 * and how to derive a secret key (for a symmetric scheme) from the random plaintext (key derivation function).
 */
public abstract class AbstractHybridConstructionKEM implements KeyEncapsulationMechanism<SymmetricKey> {
    protected EncryptionScheme scheme;
    protected KeyDerivationFunction<? extends SymmetricKey> kdf;

    public AbstractHybridConstructionKEM(EncryptionScheme scheme, KeyDerivationFunction<? extends SymmetricKey> kdf) {
        this.scheme = scheme;
        this.kdf = kdf;
    }

    /**
     * Generates random plaintexts for the underlying scheme.
     */
    protected abstract PlainText generateRandomPlaintext();

    /**
     * Returns the min entropy, of generateRandomPlaintext i.e.
     * -log2( max{Pr[Plaintext = m]} ) (where the maximum is over all possible m).
     * Rounded down to an integer.
     * <p>
     * (if you choose uniformly random among n plaintexts, it's just floor(log2(n)))
     */
    protected abstract int getPlaintextMinEntropyInBit();


    @Override
    public KeyAndCiphertext<SymmetricKey> encaps(EncryptionKey pk) {
        KeyAndCiphertext<SymmetricKey> result = new KeyAndCiphertext<>();

        //Choose random plain text and encrypt it
        PlainText pt = generateRandomPlaintext();
        CipherText encryptedPt = scheme.encrypt(pt, pk);
        KeyMaterial material = new UniqueByteKeyMaterial((UniqueByteRepresentable) pt, getPlaintextMinEntropyInBit());


        //Derive key from plaintext
        SymmetricKey key = kdf.deriveKey(material);

        //return result
        result.encapsulatedKey = encryptedPt;
        result.key = key;

        return result;
    }

    @Override
    public SymmetricKey decaps(CipherText encapsulatedKey, DecryptionKey sk) {
        //Decrypt encapsulatedKey
        PlainText pt = scheme.decrypt(encapsulatedKey, sk);
        KeyMaterial material = new UniqueByteKeyMaterial((UniqueByteRepresentable) pt, getPlaintextMinEntropyInBit());

        //derive the secret key and return it
        return kdf.deriveKey(material);
    }

    @Override
    public CipherText getEncapsulatedKey(Representation repr) {
        return scheme.getCipherText(repr);
    }

    @Override
    public EncryptionKey getEncapsulationKey(Representation repr) {
        return scheme.getEncryptionKey(repr);
    }

    @Override
    public DecryptionKey getDecapsulationKey(Representation repr) {
        return scheme.getDecryptionKey(repr);
    }
}
