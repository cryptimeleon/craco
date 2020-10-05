package de.upb.crypto.craco.abe.cp.large;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.common.interfaces.pe.PredicateEncryptionScheme;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.Map;

/**
 * Ciphertext-Policy ABE Large Universe Construction.
 * <p>
 * Abstract: In Section 3.4.2 we describe the large universe construction of
 * Waters [Wat11]. It requires monotone span programs for realizing the access
 * structures. The correctness of them is shown and we prove that these
 * constructions are selectively secure if we assume that the decisional
 * q-parallel BDHE assumption (c.f. Definition 3.10) and the decisional q-BDHE
 * assumption (c.f. Definition 3.8) hold. The schemes and proofs in this
 * section, especially the proof for the large universe scheme, are discussed in
 * more detail as in [Wat11]. For the large universe scheme we moreover appended
 * a fast decryption method.
 * <p>
 * <p>
 * Subsection 3.4.2.2 Faster decryption for large universe. The decryption as
 * defined in Construction 3.40 needs 1 + 2 · |I| pairings. Calculating pairings
 * is expensive. We have shown that we can reduce the amount of pairings during
 * the decryption to the constant factor of 2 and make the decryption thereby
 * faster.
 * <p>
 * <p>
 * [Wat11] Brent Waters. Ciphertext-policy attribute-based encryption: An
 * expressive, efficient, and provably secure realization. In Public Key
 * Cryptography, pages 53–70. Springer, 2011
 *
 * @author Marius Dransfeld (refactored by Jan Bobolz, generalized by Denis
 * Diemert)
 */
public class ABECPWat11 extends AbstractABECPWat11 implements PredicateEncryptionScheme {

    /**
     * Creates a new CipherText-Policy in the large universe.
     *
     * @param pp the public parameters of this scheme, created by
     *           {@link ABECPWat11Setup#getPublicParameters()}
     */
    public ABECPWat11(ABECPWat11PublicParameters pp) {
        super(pp);
    }

    /**
     * StandaloneRepresentable constructor.
     *
     * @param repr the representation of this object
     */
    public ABECPWat11(Representation repr) {
        super(repr);
    }

    @Override
    public ABECPWat11CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof GroupElementPlainText))
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        if (!(publicKey instanceof ABECPWat11EncryptionKey))
            throw new IllegalArgumentException("Not a valid public key for this scheme");

        GroupElementPlainText pt = (GroupElementPlainText) plainText;
        ABECPWat11EncryptionKey pk = (ABECPWat11EncryptionKey) publicKey;

        ZpElement s = zp.getUniformlyRandomUnit();

        GroupElement encryptionFactor = pp.getY().pow(s);
        // m \cdot Y^s = m \cdot E(g,g)^{ys}
        GroupElement ePrime = pt.get().op(encryptionFactor).compute();
        // g^s \in G_1
        GroupElement eTwoPrime = pp.getG().pow(s).compute();

        // compute E_i = g^{a \cdot \lambda_i} \cdot T(\rho(i))^{-s} for every attribute i
        MonotoneSpanProgram msp = new MonotoneSpanProgram(pk.getPolicy(), zp);
        Map<Integer, ZpElement> shares = msp.getShares(s);
        if (!isMonotoneSpanProgramValid(shares, msp, pp.getlMax()))
            throw new IllegalArgumentException("MSP is invalid");

        Map<BigInteger, GroupElement> elementE = computeE(s, msp, shares);

        return new ABECPWat11CipherText(pk.getPolicy(), ePrime, eTwoPrime, elementE);
    }

    @Override
    public GroupElementPlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(privateKey instanceof ABECPWat11DecryptionKey))
            throw new IllegalArgumentException("Not a valid private key for this scheme");
        if (!(cipherText instanceof ABECPWat11CipherText))
            throw new IllegalArgumentException("Not a valid ciphertext for this scheme");

        ABECPWat11DecryptionKey sk = (ABECPWat11DecryptionKey) privateKey;
        ABECPWat11CipherText c = (ABECPWat11CipherText) cipherText;
        GroupElement encryptionFactor = restoreYs(sk, c);
        return new GroupElementPlainText(c.getEPrime().op(encryptionFactor.inv()).compute());
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new GroupElementPlainText(repr, pp.getGroupGT());
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new ABECPWat11CipherText(repr, pp);
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return new ABECPWat11EncryptionKey(repr);
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return new ABECPWat11DecryptionKey(repr, pp);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ABECPWat11 && super.equals(o);
    }
}
