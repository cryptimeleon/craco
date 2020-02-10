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
 * @author Marius Dransfeld, refactoring: Fabian Eidens, Mirko Jürgens
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
     * @param shares
     * @return true if MSP is valid, else false.
     */
    private boolean isMonotoneSpanProgramValid(Map<Integer, ZpElement> shares, MonotoneSpanProgram msp, int l_max) {
        // check for line count
        if (shares.size() > l_max) {
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

        // E_prime = m \cdot Y^s \in G_T
        GroupElement E_prime = groupElementPlainText.get();
        E_prime = E_prime.op(pp.getY().pow(s));

        // E_two_prime = g^s \in G_1
        GroupElement E_two_prime = pp.getG().pow(s);
        // Get the public policy
        MonotoneSpanProgram msp = new MonotoneSpanProgram(pk.getPolicy(), zp);

        // Split s in a set of shares
        Map<Integer, ZpElement> shares = msp.getShares(s);

        if (!isMonotoneSpanProgramValid(shares, msp, pp.getT().size()))
            throw new IllegalArgumentException("MSP is invalid");

        // in G_1
        Map<BigInteger, GroupElement> E1 = new HashMap<>();
        // in G_1
        Map<BigInteger, GroupElement> E2 = new HashMap<>();

        for (Entry<Integer, ZpElement> share : shares.entrySet()) {
            // the row of the share
            BigInteger i = BigInteger.valueOf(share.getKey());
            // the party linked to this share
            Attribute rho_i = (Attribute) msp.getShareReceiver(share.getKey());
            // the share /constant
            ZpElement lambda_i = share.getValue();
            ZpElement r_i = zp.getUniformlyRandomUnit();
            // E1_i = (g^a)^lambda_i * T_{rho_i} ^-r_i
            GroupElement E1_i = pp.getG_a().pow(lambda_i);
            E1_i = E1_i.op(pp.getT().get(rho_i).pow(r_i).inv());
            // E2_i = g^r_i
            GroupElement E2_i = pp.getG().pow(r_i);

            E1.put(i, E1_i);
            E2.put(i, E2_i);
        }
        return new ABECPWat11SmallCipherText(pk.getPolicy(), E_prime, E_two_prime, E1, E2);
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof ABECPWat11SmallCipherText))
            throw new IllegalArgumentException("The cipher text is not a valid cipher text for this scheme.");
        if (!(privateKey instanceof ABECPWat11SmallDecryptionKey))
            throw new IllegalArgumentException("The private key is not a valid private key for this scheme.");

        ABECPWat11SmallCipherText c = (ABECPWat11SmallCipherText) cipherText;
        ABECPWat11SmallDecryptionKey sk = (ABECPWat11SmallDecryptionKey) privateKey;
        GroupElement D_prime = sk.getD_prime();
        GroupElement D_two_prime = sk.getD_prime2();
        Map<Attribute, GroupElement> D = sk.getD();

        MonotoneSpanProgram msp = new MonotoneSpanProgram(c.getPolicy(), zp);

        // the attributes of the decryption key
        Set<Attribute> S = D.keySet();

        if (!msp.isQualified(S)) {
            throw new UnqualifiedKeyException("The given decryption key does not satisfy the MSP");
        }

        GroupElement message = c.getE_prime();

        List<GroupElement> zList = new ArrayList<GroupElement>();

        for (Entry<Integer, ZpElement> w_i : msp.getSolvingVector(S).entrySet()) {
            // the row of the share
            BigInteger i = BigInteger.valueOf(w_i.getKey());
            // the party linked to this share
            Attribute rho_i = (Attribute) msp.getShareReceiver(w_i.getKey());

            if (!w_i.getValue().getInteger().equals(BigInteger.ZERO)) {
                GroupElement E1_i = c.getE1().get(i);
                GroupElement E2_i = c.getE2().get(i);
                GroupElement D_rho_i = D.get(rho_i);

                GroupElement map1 = pp.getE().apply(E1_i, D_two_prime);
                GroupElement map2 = pp.getE().apply(E2_i, D_rho_i);

                map1 = map1.op(map2);
                map1 = map1.pow(w_i.getValue().getInteger());
                zList.add(map1);
            }
        }
        Optional<GroupElement> reduced = zList.stream().parallel().reduce((elem1, elem2) -> elem1.op(elem2));
        GroupElement tmp = pp.getE().getGT().getNeutralElement();
        if (reduced.isPresent()) {
            tmp = reduced.get();
        }

        GroupElement map = pp.getE().apply(c.getE_two_prime(), D_prime);
        map = map.op(tmp.inv());
        return new GroupElementPlainText(message.op(map.inv()));

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
        GroupElement d_prime = g_y.op(pp.getG_a().pow(u));
        // d_prime2 = g^u \in G_T
        GroupElement d_prime2 = pp.getG().pow(u);

        Map<Attribute, GroupElement> d = new HashMap<>();
        // \forall x in attributes : d_x = T_x^u
        for (Attribute x : attributes) {
            GroupElement d_x = pp.getT().get(x).pow(u);
            d.put(x, d_x);
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
        if (o instanceof ABECPWat11Small) {
            ABECPWat11Small other = (ABECPWat11Small) o;
            return pp.equals(other.pp);
        } else {
            return false;
        }
    }

    public ABECPWat11SmallPublicParameters getPublicParameters() {
        return pp;
    }

}
