package de.upb.crypto.craco.abe.cp.small.asymmetric;

import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.EncryptionKey;
import de.upb.crypto.craco.interfaces.PlainText;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.pe.*;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.util.HashMap;
import java.util.Map;

/**
 * Asymmetric version of the small universe ABE scheme from [Wat11], Section 3.
 * According to a note in [AgrCha17], this scheme is still secure in the asymmetric setting.
 *
 * [Wat11] Brent Waters. Ciphertext-policy attribute-based encryption: An
 * expressive, efficient, and provably secure realization. In Public Key
 * Cryptography, pages 53–70. Springer, 2011
 * [AgrCha17] Shashank Agrawal and Melissa Chase. 2017. FAME: Fast Attribute-based Message Encryption.
 * In Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security (CCS ’17).
 * Association for Computing Machinery, New York, NY, USA, 665–682. DOI:https://doi.org/10.1145/3133956.3134014
 */
public class ABECPAsymSmallWat11 implements PredicateEncryptionScheme {

    /**
     * The public parameters for this CP ABE Scheme
     */
    private ABECPAsymSmallWat11PublicParameters pp;
    /**
     * Defined as Zp_{size(groupG1)}
     */
    private Zp zp;

    public ABECPAsymSmallWat11(ABECPAsymSmallWat11PublicParameters pp) {
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public ABECPAsymSmallWat11(Representation repr) {
        this.pp = new ABECPAsymSmallWat11PublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    @Override
    public ABECPAsymWat11CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof GroupElementPlainText))
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        if (!(publicKey instanceof ABECPAsymWat11EncryptionKey))
            throw new IllegalArgumentException("Not a valid public key for this scheme");

        GroupElementPlainText pt = (GroupElementPlainText) plainText;
        ABECPAsymWat11EncryptionKey pk = (ABECPAsymWat11EncryptionKey) publicKey;

        ZpElement s = zp.getUniformlyRandomUnit();

        GroupElement encryptionFactor = pp.getY().pow(s);
        // m \cdot Y^s = m \cdot E(g,g)^{ys}
        GroupElement ePrime = pt.get().op(encryptionFactor);
        // g^s \in G_1
        GroupElement eTwoPrime = pp.getG().pow(s);

        // compute E_i = g^{a \cdot \lambda_i} \cdot T(\rho(i))^{-s} for every attribute i
        MonotoneSpanProgram msp = new MonotoneSpanProgram(pk.getPolicy(), zp);
        Map<Integer, ZpElement> shares = msp.getShares(s);
        if (!isMonotoneSpanProgramValid(shares, msp, pp.getL_max()))
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
        return new GroupElementPlainText(c.getEPrime().op(encryptionFactor.inv()));
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return null;
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return null;
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return null;
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return null;
    }

    @Override
    public MasterSecret getMasterSecret(Representation repr) {
        return null;
    }

    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof ABECPAsymSmallWat11MasterSecret))
            throw new IllegalArgumentException("The master secret is not a valid master secret for this scheme.");
        if (!(kind instanceof SetOfAttributes))
            throw new IllegalArgumentException("Expected SetOfAttributes as KeyIndex");

        SetOfAttributes attributes = (SetOfAttributes) kind;
        ABECPAsymSmallWat11MasterSecret cpmsk = (ABECPAsymSmallWat11MasterSecret) msk;
        GroupElement gAlpha = cpmsk.get();

        Zp.ZpElement t = zp.getUniformlyRandomUnit();
        // K = gAlpha * (g1^{at})
        GroupElement k = gAlpha.op(pp.getGA().pow(t));
        // L = g2^t
        GroupElement l = pp.getG2().pow(t);

        Map<Attribute, GroupElement> mapKx = new HashMap<>();
        // \forall x in attributes : Kx = h_x^t
        for (Attribute x : attributes) {
            GroupElement kx = pp.getAttrs().get(x).pow(t);
            mapKx.put(x, kx);
        }
        return new ABECPAsymSmallWat11DecryptionKey(k, l, mapKx);
    }

    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof Policy))
            throw new IllegalArgumentException("Policy expected as CiphertextIndex");
        Policy policy = (Policy) cind;
        return new ABECPAsymSmallWat11EncryptionKey(policy);
    }

    @Override
    public Predicate getPredicate() {
        return null;
    }

    @Override
    public Representation getRepresentation() {
        return null;
    }
}
