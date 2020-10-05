package de.upb.crypto.craco.abe.kp.large;

import de.upb.crypto.craco.abe.accessStructure.MonotoneSpanProgram;
import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionKey;
import de.upb.crypto.craco.common.interfaces.UnqualifiedKeyException;
import de.upb.crypto.craco.abe.interfaces.Attribute;
import de.upb.crypto.craco.abe.interfaces.SetOfAttributes;
import de.upb.crypto.craco.common.interfaces.pe.CiphertextIndex;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.common.interfaces.pe.MasterSecret;
import de.upb.crypto.craco.common.interfaces.pe.Predicate;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.kem.abe.kp.large.ABEKPGPSW06KEMCipherText;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.craco.interfaces.pe.PredicateEncryptionScheme;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AbstractABEKPGPSW06 {
    protected ABEKPGPSW06PublicParameters pp;
    protected Zp zp;

    public Representation getRepresentation() {
        return pp.getRepresentation();
    }

    public EncryptionKey getEncryptionKey(Representation repr) {
        return new ABEKPGPSW06EncryptionKey(repr);
    }

    public DecryptionKey getDecryptionKey(Representation repr) {
        return new ABEKPGPSW06DecryptionKey(repr, pp);
    }

    public MasterSecret getMasterSecret(Representation repr) {
        return new ABEKPGPSW06MasterSecret(repr, pp);
    }

    /**
     * Creates a {@link DecryptionKey} out of a given {@link Policy}. This decryption key can only decrypt cipher texts
     * that are encrypted with a set of attributes that satisfy this policy.
     */
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof ABEKPGPSW06MasterSecret))
            throw new IllegalArgumentException("Not a valid master secret for this scheme");
        if (!(kind instanceof Policy))
            throw new IllegalArgumentException("Expected Policy as KeyIndex");
        ABEKPGPSW06MasterSecret kpMsk = (ABEKPGPSW06MasterSecret) msk;
        Policy policy = (Policy) kind;

        MonotoneSpanProgram msp = new MonotoneSpanProgram(policy, zp);

        Map<BigInteger, GroupElement> D = new HashMap<>();
        Map<BigInteger, GroupElement> R = new HashMap<>();
        Map<Integer, Zp.ZpElement> shares = msp.getShares(kpMsk.getY());

        for (Map.Entry<Integer, Zp.ZpElement> share : shares.entrySet()) {
            Zp.ZpElement r_i = zp.getUniformlyRandomUnit();
            BigInteger i = BigInteger.valueOf(share.getKey());

            Attribute rho_i = (Attribute) msp.getShareReceiver(share.getKey());

            Zp.ZpElement lambda_i = share.getValue();
            GroupElement rho_i_element = (GroupElement) pp.getHashToG1().hashIntoStructure(rho_i);
            // R_i = g^r_i
            GroupElement R_i = pp.getG1Generator().pow(r_i);
            // D_i = g^temp * T (rho_i)^r_i (T is the hash into g1 specified in
            // the setup)
            GroupElement D_i = pp.getG1Generator().pow(lambda_i).op(rho_i_element.pow(r_i));

            D.put(i, D_i.compute());
            R.put(i, R_i.compute());
        }

        return new ABEKPGPSW06DecryptionKey(policy, D, R);
    }

    /**
     * Generates an encryption key out of a given {@link Set Of Attributes}. This means that all plain texts that are
     * encrypted with this encryption key can only be decrypted if the {@link Policy} of the respective decryption key
     * is satisfied by this set of attributes.
     */
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof SetOfAttributes))
            throw new IllegalArgumentException("SetOfAttributes as CiphertextIndex expected");
        SetOfAttributes soa = (SetOfAttributes) cind;
        return new ABEKPGPSW06EncryptionKey(soa);
    }

    /**
     * This scheme uses a {@link SetOfAttributes} as the CipherTextIndex and a {@link Policy} as the KeyIndex.
     * See {@link PredicateEncryptionScheme} for more information about predicates.
     */
    public Predicate getPredicate() {
        return (kind, cind) -> {
            if (!(kind instanceof Policy))
                throw new IllegalArgumentException("Policy expected as KeyIndex");
            if (!(cind instanceof SetOfAttributes))
                throw new IllegalArgumentException("SetOfAttributes expected as CiphertextIndex expected");
            Policy policy = (Policy) kind;
            SetOfAttributes soa = (SetOfAttributes) cind;
            return policy.isFulfilled(soa);
        };
    }

    protected ABEKPGPSW06PublicParameters getPublicParameters() {
        return pp;
    }

    /**
     * @param attributes attribute set \omega
     * @param s          random number used in the encryption
     * @return { E_i = T(i)^s }_{i \in \omega}
     */
    protected Map<Attribute, GroupElement> restoreE(SetOfAttributes attributes, Zp.ZpElement s) {
        // i -> T(i)
        Function<Attribute, GroupElement> hash = i -> (GroupElement) pp.getHashToG1().hashIntoStructure(i);

        // E_i = T(i)^s
        return attributes
                .parallelStream()
                .collect(Collectors.toConcurrentMap(i -> i, i -> hash.apply(i).pow(s).compute()));
    }

    /**
     * Restores Y^{s}, which is the noise factor for the {@link ABEKPGPSW06} encryption. Y^s is needed to
     * decrypt a ciphertext or to decapsulate a key.
     *
     * @param ct ciphertext or encapsulated key for which Y^s shall be restored
     * @param sk decryption key of KP-ABE scheme
     * @return Y^s as described above
     */
    protected GroupElement restoreYs(ABEKPGPSW06DecryptionKey sk, ABEKPGPSW06KEMCipherText ct) {
        // obtain MSP corresponding to the decryption key's policy
        MonotoneSpanProgram msp = new MonotoneSpanProgram(sk.getPolicy(), zp);
        // obtain attributes ct was computed with
        Set<Attribute> omega = ct.getAttributes();

        Map<BigInteger, GroupElement> dMap = sk.getDElementMap();
        Map<BigInteger, GroupElement> rMap = sk.getRElementMap();

        // check if omega is qualified for the MSP
        if (!msp.isQualified(omega)) {
            throw new UnqualifiedKeyException("The ciphertext's attributes do not satisfy the private key's policy.");
        }

        // obtain solving vector w s.t. internal matrix M of MSP fulfills: w * M = (1,0,...,0)
        // note that w_i = 0 for \rho(i) \not\in \omega
        Map<Integer, Zp.ZpElement> solvingVector = msp.getSolvingVector(omega);

        /*
         * Compute Y^s = Z^{-1}, Z = \prod_{i \in \omega} (e(R_i, E_{\rho(i)}) / e(D_i, E''))^{w_i}
         *
         * We optimized the computation given in the original work, in detail:
         *
         * Optimization numerator: pull exponentiation in group G_1, e(R_i^{w_i}, E_{\rho(i)})
         * Optimization denominator:
         *  1) pull exponentiation in group G_1, e(D_i^{- w_i}, E'')
         *  2) pull product in G_1, as well, e( \prod_{i \in \omega} D_i^{- w_i}, E'')
         *
         * Overall: Z = [\prod_{i \in \omega} e(R_i^{w_i}, E_rho_i) ] * e( \prod_{i \in \omega} D_i^{- w_i}, E'')
         *
         * Hence, Y^s = Z^{-1} = [\prod_{i \in \omega} e(R_i^{-w_i}, E_rho_i) ] * e( \prod_{i \in \omega} D_i^{w_i},
         * E'')
         */

        // get index i of solving vector entry
        Function<Map.Entry<Integer, Zp.ZpElement>, BigInteger> index = elem -> BigInteger.valueOf(elem.getKey());
        // get solving vector value w_i of the given element
        Function<Map.Entry<Integer, Zp.ZpElement>, Zp.ZpElement> value = Map.Entry::getValue;
        // get share reciever rho(i) of given solving vector element
        Function<Map.Entry<Integer, Zp.ZpElement>, Attribute> rho = elem ->
                (Attribute) msp.getShareReceiver(elem.getKey());

        // supplier of all elements (i, w_i) of the solving vector s.t. w_i = 0.
        // w_i = 0 iff \rho(i) \not\in \omega and therefore these terms don't matter for the product. Moreover,
        // the terms would be 1 anyway.
        Supplier<Stream<Map.Entry<Integer, Zp.ZpElement>>> nonZeroSVElements = () ->
                solvingVector.entrySet().parallelStream()
                        .filter(elem -> !value.apply(elem).getInteger().equals(BigInteger.ZERO));

        // \prod_{i \in \omega} e(R_i^{-w_i}, E_{\rho(i)})
        GroupElement factor1 = nonZeroSVElements.get()
                // map (i, w_i) -> e(R_i^{-w_i}, E_{\rho(i)})
                .map(elem -> pp.getBilinearMap()
                        .apply(
                                rMap.get(index.apply(elem))
                                        .pow(value.apply(elem)).inv(),
                                ct.getEElementMap().get(rho.apply(elem))
                        )
                ).reduce(pp.getGroupGT().getNeutralElement(), GroupElement::op);

        // \prod_{i \in \omega} D_i^{w_i}
        GroupElement dIProd = nonZeroSVElements.get()
                // map solving vector entry (i, w_i) -> D_i^{w_i}
                .map(elem -> dMap.get(index.apply(elem)).pow(value.apply(elem)))
                // compute product
                .reduce(pp.getGroupG1().getNeutralElement(), GroupElement::op);

        // e( \prod_{i \in \omega} D_i^{- w_i}, E'')
        GroupElement factor2 = pp.getBilinearMap().apply(dIProd, ct.getETwoPrime());

        return factor1.op(factor2).compute();
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
        AbstractABEKPGPSW06 other = (AbstractABEKPGPSW06) o;
        return Objects.equals(pp, other.pp);
    }
}
