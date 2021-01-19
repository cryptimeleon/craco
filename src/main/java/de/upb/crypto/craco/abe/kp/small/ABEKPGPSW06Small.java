package de.upb.crypto.craco.abe.kp.small;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.PlainText;
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
 * Small universe tree KP-ABE Construction
 * <p>
 * In the next section we will describe the KP-ABE scheme that Goyal et. al.
 * presented in their paper [GPSW06]. The Fuzzy IBE scheme presented in 3.2.1 is
 * a special case of the this KP-ABE scheme. We will first describe the key
 * generation process and give a rough overview over the decryption of
 * ciphertexts in the KP-ABE scheme in comparison to the Fuzzy IBE scheme. Then
 * we will present the construction and prove its correctness and security. The
 * Fuzzy IBE small universe construction only allows a very rigid Key-Policy
 * which is a single threshold gate with a fixed value. Only the attribute nodes
 * of this threshold gate may be chosen freely. This is a special case of an
 * access tree. As the generalization of this, the KP-ABE scheme allows any
 * access tree to be chosen as its Key-Policy.
 * <p>
 * [GPSW06] Vipul Goyal, Omkant Pandey, Amit Sahai, and Brent Waters.
 * Attribute-based encryption for fine-grained access control of encrypted data.
 * In ACM Conference on Computer and Communications Security, pages 89–98. ACM,
 * 2006.
 *
 *
 */
public class ABEKPGPSW06Small implements PredicateEncryptionScheme {

    private ABEKPGPSW06SmallPublicParameters pp;
    private Zp zp;

    public ABEKPGPSW06Small(ABEKPGPSW06SmallPublicParameters pp) {
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public ABEKPGPSW06Small(Representation repr) {
        this.pp = new ABEKPGPSW06SmallPublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    @Override
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof GroupElementPlainText))
            throw new IllegalArgumentException("Not a valid plain text for this scheme");
        if (!(publicKey instanceof ABEKPGPSW06SmallEncryptionKey))
            throw new IllegalArgumentException("Not a valid priate key or this scheme");

        ABEKPGPSW06SmallEncryptionKey pk = (ABEKPGPSW06SmallEncryptionKey) publicKey;
        GroupElementPlainText pt = (GroupElementPlainText) plainText;

        ZpElement s = zp.getUniformlyRandomUnit();

        // m*Y^s
        GroupElement E_prime = pt.get().op(pp.getY().pow(s)).compute();

        // The attributes of the key w' \subset universe
        SetOfAttributes attributes = pk.getAttributes();
        // E_i = T_i^s i \in w'
        HashMap<Attribute, GroupElement> E = new HashMap<>();
        for (Attribute i : attributes) {
            GroupElement E_i = pp.getT().get(i).pow(s);
            E.put(i, E_i.compute());
        }
        return new ABEKPGPSW06SmallCipherText(E_prime, E);
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof ABEKPGPSW06SmallCipherText))
            throw new IllegalArgumentException("Not a valid cipher text for this scheme");
        if (!(privateKey instanceof ABEKPGPSW06SmallDecryptionKey))
            throw new IllegalArgumentException("Not a valid private key for this scheme");

        ABEKPGPSW06SmallDecryptionKey sk = (ABEKPGPSW06SmallDecryptionKey) privateKey;
        ABEKPGPSW06SmallCipherText ct = (ABEKPGPSW06SmallCipherText) cipherText;

        MonotoneSpanProgram msp = new MonotoneSpanProgram(sk.getPolicy(), zp);

        Set<Attribute> S = ct.getE().keySet();
        Map<BigInteger, GroupElement> D = sk.getD();

        List<GroupElement> zList = new ArrayList<GroupElement>();

        Map<Integer, ZpElement> solvingVector = msp.getSolvingVector(S);

        for (Entry<Integer, ZpElement> a : solvingVector.entrySet()) {
            ZpElement alpha = a.getValue();
            BigInteger i = BigInteger.valueOf(a.getKey());
            Attribute rho_i = (Attribute) msp.getShareReceiver(a.getKey());

            // For optimization skip the computations if alpha is zero
            if (!alpha.equals(zp.getZeroElement())) {

                try {
                    GroupElement factor = pp.getE().apply(D.get(i), ct.getE().get(rho_i)).pow(alpha);
                    zList.add(factor);
                } catch (NullPointerException e) {
                    throw new WrongAccessStructureException(
                            "The attributes provided in the private key are not in the universe.");
                }
            }
        }

        GroupElement tmp;
        tmp = zList.stream().parallel().reduce(GroupElement::op)
                .orElseThrow(() -> new IllegalStateException("Empty solving vector!"));
        return new GroupElementPlainText(ct.getE_prime().op(tmp.inv()).compute());
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
        return new ABEKPGPSW06SmallCipherText(repr, pp);
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return new ABEKPGPSW06SmallEncryptionKey(repr);
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return new ABEKPGPSW06SmallDecryptionKey(repr, pp);
    }

    @Override
    public MasterSecret getMasterSecret(Representation repr) {
        return new ABEKPGPSW06SmallMasterSecret(repr, pp);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a {@link DecryptionKey} out of a given {@link Policy}. This
     * decryption key can only decrypt cipher texts that are encrypted with a
     * set of attributes that satisfy this policy.
     */
    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof ABEKPGPSW06SmallMasterSecret))
            throw new IllegalArgumentException("Not a valid MasterSecret for this scheme");
        if (!(kind instanceof Policy))
            throw new IllegalArgumentException("Policy expected as KeyIndex");

        ABEKPGPSW06SmallMasterSecret kpmsk = (ABEKPGPSW06SmallMasterSecret) msk;
        Policy policy = (Policy) kind;

        MonotoneSpanProgram msp = new MonotoneSpanProgram(policy, zp);

        Map<BigInteger, GroupElement> D = new HashMap<>();

        Map<Integer, ZpElement> shares = msp.getShares(kpmsk.getY());

        for (Entry<Integer, ZpElement> share : shares.entrySet()) {
            try {
                BigInteger i = BigInteger.valueOf(share.getKey());
                Attribute rho_i = (Attribute) msp.getShareReceiver(share.getKey());
                ZpElement M_i_u = share.getValue();

                ZpElement t_p_i = kpmsk.getT().get(rho_i);
                M_i_u = (ZpElement) M_i_u.div(t_p_i);

                D.put(i, pp.getG().pow(M_i_u).compute());

            } catch (NullPointerException e) {
                throw new WrongAccessStructureException(
                        "The attributes provided in the policy are not in the universe.");
            }
        }

        return new ABEKPGPSW06SmallDecryptionKey(policy, D);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Generates an encryption key out of a given {@link Set Of Attributes}.
     * This means that all plain texts that are encrypted with this encryption
     * key can only be decrypted if the {@link Policy} of the respective
     * decryption key is satisfied by this set of attributes.
     */
    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof SetOfAttributes))
            throw new IllegalArgumentException("SetOfAttributes expected as CiphertextIndex");
        SetOfAttributes soa = (SetOfAttributes) cind;
        return new ABEKPGPSW06SmallEncryptionKey(soa);
    }

    @Override
    public Predicate getPredicate() {
        return (kind, cind) -> {
            if (!(kind instanceof Policy))
                throw new IllegalArgumentException("Policy expected as KeyIndex");
            if (!(cind instanceof SetOfAttributes))
                throw new IllegalArgumentException("SetOfAttributes as CiphertextIndex expected");
            Policy policy = (Policy) kind;
            SetOfAttributes soa = (SetOfAttributes) cind;
            return policy.isFulfilled(soa);
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
        ABEKPGPSW06Small other = (ABEKPGPSW06Small) o;
        return Objects.equals(pp, other.pp);
    }

    public ABEKPGPSW06SmallPublicParameters getPublicParameters() {
        return pp;
    }

}
