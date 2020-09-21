package de.upb.crypto.craco.kem.abe.cp.large;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.abe.cp.large.*;
import de.upb.crypto.craco.interfaces.*;
import de.upb.crypto.craco.interfaces.pe.PredicateKEM;
import de.upb.crypto.craco.kem.KeyMaterial;
import de.upb.crypto.craco.kem.UniqueByteKeyMaterial;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Map;

/**
 * A KEM based on the ciphertext-policy large universe construction ({@link ABECPWat11}.
 * <p>
 * For the basic idea of the construction consider a ciphertext (E', E'', (E_i)_{i}) of {@link ABECPWat11}, where E' = m
 * * Y^s for some message m, random number s and Y defined in the scheme's setup {@link ABECPWat11Setup}. The KEM now
 * outputs E'
 * dropping factor m as a key, i.e. Y^s, and (E'', (E_i)_{i}) as its encapsulation. The decryption of {@link ABECPWat11}
 * just recovers Y^s from (E'', (E_i)_{i}) and computes E' / Y^s to obtain m. In the same way we can use this to
 * decapsulate the key Y^s.
 * <p>
 * This scheme only supplies {@link KeyMaterial}. It needs to be used in combination with a KDF to obtain a symmetric
 * key.
 *
 * @author Denis Diemert (based on {@link ABECPWat11})
 */
public class ABECPWat11KEM extends AbstractABECPWat11 implements PredicateKEM<KeyMaterial> {

    public ABECPWat11KEM(ABECPWat11PublicParameters pp) {
        super(pp);
    }

    public ABECPWat11KEM(Representation repr) {
        // generate pp from repr and call super constructor
        super(repr);
    }

    /**
     * Essentially {@link ABECPWat11#encrypt(PlainText, EncryptionKey)} but instead of encrypting some {@link PlainText}
     * m, it outputs the first component of the ciphertext ({@code ePrime} from {@link ABECPWat11CipherText}) 
     * dropping the factor m as a key
     * along with the second ({@link ABECPWat11KEMCipherText#eTwoPrime}) and third ({@link ABECPWat11KEMCipherText}
     * #E) component as the encapsulation of this key.
     *
     * @param publicKey {@link ABECPWat11EncryptionKey} created by
     *                  {@link ABECPWat11#generateEncryptionKey(de.upb.crypto.craco.interfaces.pe.CiphertextIndex)}
     * @return (Y ^ s, ( g ^ s, ( g ^ { a \ lambda_i } * T ( \ rho ( i))^{-s})))
     */
    public KeyAndCiphertext<KeyMaterial> encaps(EncryptionKey publicKey) {
        if (!(publicKey instanceof ABECPWat11EncryptionKey)) {
            throw new IllegalArgumentException("Not a valid public key type for this scheme");
        }

        ABECPWat11EncryptionKey pk = (ABECPWat11EncryptionKey) publicKey;

        Zp.ZpElement s = zp.getUniformlyRandomUnit();
        logger.debug("Generated random secret " + s);

        // message: Y^s = e(g,g)^{ys} \in G_T
        GroupElement kemMessage = pp.getY().pow(s);

        // first part of the ciphertext of the key, see ABECPWat11
        // E''= g^s \in G_1
        GroupElement E_two_prime = pp.getG().pow(s);

        MonotoneSpanProgram msp = new MonotoneSpanProgram(pk.getPolicy(), zp);
        Map<Integer, Zp.ZpElement> shares = msp.getShares(s);
        if (!isMonotoneSpanProgramValid(shares, msp, pp.getlMax()))
            throw new IllegalArgumentException("MSP is invalid");

        // second part of the ciphertext of the key, see ABECPWat11
        // G_1 \owns E_i = g^{a \cdot \lambda_i} \cdot T(\phi(i))^{-s}
        Map<BigInteger, GroupElement> E = computeE(s, msp, shares);

        KeyAndCiphertext<KeyMaterial> output = new KeyAndCiphertext<>();

        // use log_2(|G_T|) as min-entropy of source, because kemMessage is distributed uniformly at random in G_T
        output.key = new UniqueByteKeyMaterial(kemMessage.compute(), pp.getGroupGT().size().bitLength());
        output.encapsulatedKey = new ABECPWat11KEMCipherText(pk.getPolicy(), E_two_prime.compute(), E);

        return output;
    }

    /**
     * Restores Y^s = e(g,g)^{ys} as in {@link ABECPWat11#decrypt(CipherText, DecryptionKey)} and returns it as a key.
     *
     * @param encapsulatedKey encapsulation of Y^s
     * @param secretKey       decapsulation key
     * @return key material Y^s
     * @throws UnqualifiedKeyException thrown if the attributes given by the decryption key do not match the
     *                                 ciphertext's policy
     */
    public KeyMaterial decaps(CipherText encapsulatedKey, DecryptionKey secretKey) throws UnqualifiedKeyException {
        if (!(secretKey instanceof ABECPWat11DecryptionKey))
            throw new IllegalArgumentException("Not a valid private key for this scheme");
        if (!(encapsulatedKey instanceof ABECPWat11KEMCipherText))
            throw new IllegalArgumentException("Not a valid ciphertext for this scheme");

        ABECPWat11DecryptionKey sk = (ABECPWat11DecryptionKey) secretKey;
        ABECPWat11KEMCipherText encapsKey = (ABECPWat11KEMCipherText) encapsulatedKey;

        return new UniqueByteKeyMaterial(restoreYs(sk, encapsKey), pp.getGroupGT().size().bitLength());
    }

    public CipherText getEncapsulatedKey(Representation repr) {
        return new ABECPWat11KEMCipherText(repr, pp);
    }

    public EncryptionKey getEncapsulationKey(Representation repr) {
        return new ABECPWat11EncryptionKey(repr);
    }

    public DecryptionKey getDecapsulationKey(Representation repr) {
        return new ABECPWat11DecryptionKey(repr, pp);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null)
            return false;
        if (getClass() != o.getClass())
            return false; 
        return super.equals(o);
    }
}
