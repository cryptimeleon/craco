package de.upb.crypto.craco.abe.cp.small;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.interfaces.pe.*;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

/**
 * Ciphertext-Policy ABE Small Universe Construction.
 * <p>
 * Abstract: In Section 3.4.1 we describe the large universe construction of
 * Waters [Wat11]. It requires monotone span programs for realizing the access
 * structures. The correctness of them is shown and we prove that these
 * constructions are selectively secure if we assume that the decisional
 * q-parallel BDHE assumption (c.f. Definition 3.10) and the decisional q-BDHE
 * assumption (c.f. Definition 3.8) hold. A efficient small universe
 * Ciphertext-Policy ABE construction of Waters [Wat11] is presented. Efficient
 * means that the ciphertext size and the runtime of Enc and Dec grow linearly
 * with the complexity of the access structure.
 * <p>
 * <p>
 * [Wat11] Brent Waters. Ciphertext-policy attribute-based encryption: An
 * expressive, efficient, and provably secure realization. In Public Key
 * Cryptography, pages 53–70. Springer, 2011
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens, Raphael Heitjohann
 */
public class ABECPWat11Small implements PredicateEncryptionScheme {

    /**
     * The public parameters for this CP ABE Scheme
     */
    private ABECPWat11SmallPublicParameters pp;
    /**
     * Defined as Zp_{size(groupG1)}
     */
    private Zp zp;

    public ABECPWat11Small(ABECPWat11SmallPublicParameters pp) {
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public ABECPWat11Small(Representation repr) {
        this.pp = new ABECPWat11SmallPublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    /**
     * Checks if the number of shared attributes (the lines in the MSP) are
     * valid and if the MSP is injective (all lines are different attributes).
     *
     * @param shares maps share indices to the shares
     * @param msp the msp to check
     * @param lMax the maximum number of shares allowed
     * @return true if MSP is valid, else false.
     */
    private boolean isMonotoneSpanProgramValid(Map<Integer, ZpElement> shares, MonotoneSpanProgram msp, int lMax) {
        // check for line count
        if (shares.size() > lMax) {
            return false;
        } else {
            Set<Attribute> attributes = new HashSet<>();
            for (Entry<Integer, ZpElement> share : shares.entrySet()) {
                if (attributes.contains((Attribute) msp.getShareReceiver(share.getKey()))) {
                    return false;
                } else {
                    attributes.add((Attribute) msp.getShareReceiver(share.getKey()));
                }
            }
            return true;
        }
    }

    @Override
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof GroupElementPlainText))
            throw new IllegalArgumentException("The plain text is not a valid plain text for this scheme.");
        if (!(publicKey instanceof ABECPWat11SmallEncryptionKey))
            throw new IllegalArgumentException("The public key is not a valid public key for this scheme.");

        ABECPWat11SmallEncryptionKey pk = (ABECPWat11SmallEncryptionKey) publicKey;
        GroupElementPlainText groupElementPlainText = (GroupElementPlainText) plainText;

        ZpElement s = zp.getUniformlyRandomUnit();

        // C = M \cdot e(g,g)^{\alpha s} \in G_T
        GroupElement c = groupElementPlainText.get();
        c = c.op(pp.geteGGAlpha().pow(s)).compute();

        // C' = g^s \in G_1
        GroupElement cPrime = pp.getG().pow(s).compute();
        // Get the public policy
        MonotoneSpanProgram msp = new MonotoneSpanProgram(pk.getPolicy(), zp);

        // Split s in a set of shares
        Map<Integer, ZpElement> shares = msp.getShares(s);

        if (!isMonotoneSpanProgramValid(shares, msp, pp.getH().size()))
            throw new IllegalArgumentException("MSP is invalid");

        // Mapping C in G_1
        Map<BigInteger, GroupElement> mapC = new HashMap<>();
        // Mapping D in G_1
        Map<BigInteger, GroupElement> mapD = new HashMap<>();

        for (Entry<Integer, ZpElement> share : shares.entrySet()) {
            // the row of the share
            BigInteger i = BigInteger.valueOf(share.getKey());
            // the party linked to this share
            Attribute rhoI = (Attribute) msp.getShareReceiver(share.getKey());
            // the share /constant
            ZpElement lambdaI = share.getValue();
            ZpElement rI = zp.getUniformlyRandomUnit();
            // C_i = (g^a)^\lambda_i * h_{\rho_i}^{-r_i}
            GroupElement cI = pp.getgA().pow(lambdaI);
            cI = cI.op(pp.getH().get(rhoI).pow(rI).inv()).compute();
            // D_i = g^r_i
            GroupElement dI = pp.getG().pow(rI).compute();

            mapC.put(i, cI);
            mapD.put(i, dI);
        }
        return new ABECPWat11SmallCipherText(pk.getPolicy(), c, cPrime, mapC, mapD);
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof ABECPWat11SmallCipherText))
            throw new IllegalArgumentException("The cipher text is not a valid cipher text for this scheme.");
        if (!(privateKey instanceof ABECPWat11SmallDecryptionKey))
            throw new IllegalArgumentException("The private key is not a valid private key for this scheme.");

        ABECPWat11SmallCipherText c = (ABECPWat11SmallCipherText) cipherText;
        ABECPWat11SmallDecryptionKey sk = (ABECPWat11SmallDecryptionKey) privateKey;
        GroupElement k = sk.getK();
        GroupElement l = sk.getL();
        Map<Attribute, GroupElement> mapK = sk.getMapK();

        MonotoneSpanProgram msp = new MonotoneSpanProgram(c.getPolicy(), zp);

        // the attributes of the decryption key
        Set<Attribute> S = mapK.keySet();

        if (!msp.isQualified(S)) {
            throw new UnqualifiedKeyException("The given decryption key does not satisfy the MSP");
        }

        GroupElement message = c.getC();

        // List that accumulates factors for the product computation of the left side of the decryption equation
        // The evaluation can then automatically be parallelized using Java streams
        List<GroupElement> productList = new ArrayList<GroupElement>();

        for (Entry<Integer, ZpElement> omegaI : msp.getSolvingVector(S).entrySet()) {
            // the row of the share
            BigInteger i = BigInteger.valueOf(omegaI.getKey());
            // the party linked to this share
            Attribute rhoI = (Attribute) msp.getShareReceiver(omegaI.getKey());

            if (!omegaI.getValue().getInteger().equals(BigInteger.ZERO)) {
                GroupElement cI = c.getMapC().get(i);
                GroupElement dI = c.getMapD().get(i);
                GroupElement kRhoI = mapK.get(rhoI);

                // e(C_i, L)
                GroupElement map1 = pp.getE().apply(cI, l);
                // e(D_i, K_{\rho(i)}
                GroupElement map2 = pp.getE().apply(dI, kRhoI);

                // e(C_i, L) \cdot e(D_i, K_{\rho(i)}
                map1 = map1.op(map2);
                // (e(C_i, L) \cdot e(D_i, K_{\rho(i)})^{\omega_i}
                map1 = map1.pow(omegaI.getValue().getInteger());
                productList.add(map1);
            }
        }
        Optional<GroupElement> reduced = productList.stream().parallel().reduce(GroupElement::op);
        GroupElement tmp = pp.getE().getGT().getNeutralElement();
        if (reduced.isPresent()) {
            tmp = reduced.get();
        }

        // e(C', K)
        GroupElement map = pp.getE().apply(c.getcPrime(), k);
        // e(C', K) / (\prod_{i \in I}{(e(C_i, L) \cdot e(D_i, K_{\rho(i)})^{\omega_i}} = e(g,g)^{\alpha s}
        map = map.op(tmp.inv());
        return new GroupElementPlainText(message.op(map.inv()).compute());
    }

    @Override
    public Representation getRepresentation() {
        return pp.getRepresentation();
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new GroupElementPlainText(repr, pp.getGroupGT());
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new ABECPWat11SmallCipherText(repr, pp);
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return new ABECPWat11SmallEncryptionKey(repr);
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return new ABECPWat11SmallDecryptionKey(repr, pp);
    }

    @Override
    public MasterSecret getMasterSecret(Representation repr) {
        return new ABECPWat11SmallMasterSecret(repr, pp.getGroupG1());
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a decryption key out of a given {@link SetOfAttributes}. This
     * decryption key can only decrypt cipher texts that are encrypted with
     * policies that are satisfied by this set of attributes.
     */
    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof ABECPWat11SmallMasterSecret))
            throw new IllegalArgumentException("The master secret is not a valid master secret for this scheme.");
        if (!(kind instanceof SetOfAttributes))
            throw new IllegalArgumentException("Expected SetOfAttributes as KeyIndex");

        SetOfAttributes attributes = (SetOfAttributes) kind;
        ABECPWat11SmallMasterSecret cpmsk = (ABECPWat11SmallMasterSecret) msk;
        GroupElement g_y = cpmsk.get();

        ZpElement u = zp.getUniformlyRandomUnit();
        // d_prime = g_y * (g_a^u)
        GroupElement d_prime = g_y.op(pp.getgA().pow(u)).compute();
        // d_prime2 = g^u \in G_T
        GroupElement d_prime2 = pp.getG().pow(u).compute();

        Map<Attribute, GroupElement> d = new HashMap<>();
        // \forall x in attributes : d_x = T_x^u
        for (Attribute x : attributes) {
            GroupElement d_x = pp.getH().get(x).pow(u);
            d.put(x, d_x.compute());
        }
        return new ABECPWat11SmallDecryptionKey(d, d_prime, d_prime2);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Generates an encryption key out of a given {@link Policy}. This means
     * that all plain texts that are encrypted with this encryption key can only
     * be decrypted if the set of attributes of the respective decryption key
     * satisfy this policy.
     */
    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof Policy))
            throw new IllegalArgumentException("Policy expected as CiphertextIndex");
        Policy policy = (Policy) cind;
        return new ABECPWat11SmallEncryptionKey(policy);
    }

    /**
     * {@inheritDoc}
     * <p>
     * This scheme uses a {@link Policy} as the CipherTextIndex and a
     * {@link SetOfAttributes} as the KeyIndex.
     */
    @Override
    public Predicate getPredicate() {
        return new Predicate() {
            @Override
            public boolean check(KeyIndex kind, CiphertextIndex cind) {
                if (!(cind instanceof Policy))
                    throw new IllegalArgumentException("Policy expected as CiphertextIndex");
                if (!(kind instanceof SetOfAttributes))
                    throw new IllegalArgumentException("SetOfAttributes expected as KeyIndex ");
                Policy policy = (Policy) cind;
                SetOfAttributes soa = (SetOfAttributes) kind;
                return policy.isFulfilled(soa);
            }
        };
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pp == null) ? 0 : pp.hashCode());
        result = prime * result + ((zp == null) ? 0 : zp.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        ABECPWat11Small other = (ABECPWat11Small) o;
        return Objects.equals(pp, other.pp);
    }

    public ABECPWat11SmallPublicParameters getPublicParameters() {
        return pp;
    }

}
