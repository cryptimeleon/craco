package de.upb.crypto.craco.abe.cp.large.distributed;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11DecryptionKey;
import de.upb.crypto.craco.common.utils.LagrangeUtil;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.DistributedEncryptionScheme;
import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.abe.distributed.KeyShare;
import de.upb.crypto.craco.interfaces.abe.distributed.MasterKeyShare;
import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.craco.interfaces.pe.MasterSecret;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.util.*;

/**
 * Distributed Ciphertext-Policy ABE scheme Described in the CrACo Document
 * <p>
 * The DistributedABECPWat11 can be seen as an extension to the normal
 * {@link ABECPWat11}, where the {@link MasterSecret} is shared
 * among a well defined amount of servers. These servers each hold a
 * {@link MasterKeyShare} and the user can combine <code>t</code>
 * {@link MasterKeyShare} to request a {@link DecryptionKey}, where
 * <code>t</code> is defined by
 * {@link DistributedEncryptionScheme#getMinAmountToRecreate()}.
 * <p>
 * THe user can set up such a scheme by executing the KeyGen algorithm in
 * {@link DistributedABECPWat11Setup#doKeyGen(int, int, int, int, int, boolean)}. This
 * will yield the {@link DistributedABECPWat11PublicParameters} as well as the
 * {@link MasterKeyShare}.
 * <p>
 * Additionally, this scheme can be used as a normal
 * {@link ABECPWat11}, so instead of combining <code>t</code>
 * {@link MasterKeyShare}, the user can request a {@link DecryptionKey} by
 * calling
 * {@link ABECPWat11#generateDecryptionKey(MasterSecret, KeyIndex)}
 * with the {@link MasterSecret} of
 * {@link DistributedABECPWat11Setup#getMasterSecret()}.
 *
 * @author Christian Stroh, refactoring: Fabian Eidens, Mirko Jürgens
 */
public class DistributedABECPWat11 extends ABECPWat11 implements DistributedEncryptionScheme {

    private static final Logger log = LogManager.getLogger("DistributedCPLogger");

    private DistributedABECPWat11PublicParameters pp;
    private Zp zp;

    public DistributedABECPWat11(Representation repr) {
        super(new DistributedABECPWat11PublicParameters(repr));
        this.pp = new DistributedABECPWat11PublicParameters(repr);
        this.zp = new Zp(pp.getGroupG1().size());
    }

    public DistributedABECPWat11(DistributedABECPWat11PublicParameters pp) {
        super(pp);
        this.pp = pp;
        this.zp = new Zp(pp.getGroupG1().size());
    }

    @Override
    public boolean shareVerify(KeyShare pKeyShare) {
        if (!(pKeyShare instanceof DistributedABECPWat11KeyShare))
            throw new IllegalArgumentException("This KeyShare is not a correct KeyShare");
        DistributedABECPWat11KeyShare keyShare = (DistributedABECPWat11KeyShare) pKeyShare;

        GroupElement result;

        int xi = keyShare.getServerID();
        log.debug("Starting shareVerify for KeyShare from serverID: " + xi);

        GroupElement D_prime_xi = keyShare.getD_prime();

        GroupElement D_doublePrime_xi = keyShare.getD_two_prime();

        Map<Attribute, GroupElement> D_xi = keyShare.getD_xi();

        result = pp.getE().apply(D_prime_xi, pp.getG());

        result = result.op(pp.getE().apply(pp.getgA(), D_doublePrime_xi).inv());
        log.debug("Calculated e(D'_serverID, g)/e(g_a, D''_serverID) = e(g,g)^tmp_server_ID: " + result);
        if (!result.equals(pp.getVerificationKeys().get(xi))) {
            return false;
        }

        for (Attribute i : keyShare.getKeyIndex()) {
            result = pp.getE().apply(pp.getG(), D_xi.get(i));

            if (!result
                    .equals(pp.getE().apply(D_doublePrime_xi, (GroupElement) pp.getHashToG1().hashIntoStructure(i)))) {

                return false;
            }
        }

        return true;
    }

    @Override
    public DecryptionKey combineKeyShares(List<KeyShare> ks) {
        if (ks.size() < pp.getThreshold())
            throw new IllegalArgumentException(
                    "Need at least " + pp.getThreshold() + " shares tp recreate private key");

        if (!(ks.iterator().next() instanceof DistributedABECPWat11KeyShare))
            throw new IllegalArgumentException("Invalid KeyShare");

        List<DistributedABECPWat11KeyShare> keyShares = new ArrayList<>();
        ks.forEach(e -> keyShares.add((DistributedABECPWat11KeyShare) e));

        SetOfAttributes attributes = keyShares.iterator().next().getKeyIndex();
        log.debug("Creating DecryptionKey from the given KeyShares ");

        if (attributes.size() > pp.getN()) {
            throw new IllegalArgumentException(
                    "Attribute count cannot be greater than " + pp.getN() + " (is " + attributes.size() + ")");
        }

        // run shareVerify on all keyShares
        for (DistributedABECPWat11KeyShare keyShare : keyShares) {
            if (shareVerify(keyShare) == false) {
                throw new IllegalArgumentException(
                        "shareVerify failed for key share of server " + keyShare.getServerID());
            }
        }

        // subset of the input, but of the size t
        Set<DistributedABECPWat11KeyShare> s_prime = new HashSet<>(getMinAmountToRecreate());
        Set<BigInteger> s_prime_server_ids = new HashSet<>();
        int count = 0;
        for (Iterator<DistributedABECPWat11KeyShare> iterator = keyShares
                .iterator(); count < getMinAmountToRecreate(); count++) {
            DistributedABECPWat11KeyShare distributedCPKeyShare = iterator.next();
            s_prime.add(distributedCPKeyShare);
            s_prime_server_ids.add(BigInteger.valueOf(distributedCPKeyShare.getServerID()));
        }

        GroupElement D_prime = pp.getE().getG1().getNeutralElement();

        GroupElement D_doublePrime = pp.getE().getG1().getNeutralElement();

        final Map<Attribute, GroupElement> D = new HashMap<>();
        for (Attribute i : attributes) {
            D.put(i, pp.getE().getG1().getNeutralElement());
        }

        for (DistributedABECPWat11KeyShare share : s_prime) {
            // not s_prime. Merge server ids in order of the keyshares

            BigInteger delta_xi_S_prime_zero = LagrangeUtil.computeCoefficient(BigInteger.valueOf(share.getServerID()),
                    s_prime_server_ids, BigInteger.valueOf(0), zp);

            // interpolate D'
            GroupElement D_prime_xi = share.getD_prime();
            D_prime_xi = D_prime_xi.pow(delta_xi_S_prime_zero);
            D_prime = D_prime.op(D_prime_xi);

            // interpolate D''
            GroupElement D_doublePrime_xi = share.getD_two_prime();
            D_doublePrime_xi = D_doublePrime_xi.pow(delta_xi_S_prime_zero);
            D_doublePrime = D_doublePrime.op(D_doublePrime_xi);

            // interpolate D (containing all D_i)
            Map<Attribute, GroupElement> D_xi = share.getD_xi();
            for (Attribute i : attributes) {
                GroupElement D_xi_i = D_xi.get(i);
                D_xi_i = D_xi_i.pow(delta_xi_S_prime_zero);
                D.put(i, D.get(i).op(D_xi_i));
            }
        }

        return new ABECPWat11DecryptionKey(D, D_prime, D_doublePrime);
    }

    @Override
    public KeyShare generateKeyShare(MasterKeyShare mks, KeyIndex kind) {
        if (!(mks instanceof DistributedABECPWat11MasterKeyShare))
            throw new IllegalArgumentException("Not a valid MasterKeyShare for this scheme");
        if (!(kind instanceof SetOfAttributes))
            throw new IllegalArgumentException("SetOfAttributes expected as KeyIndex");

        SetOfAttributes attributes = (SetOfAttributes) kind;
        DistributedABECPWat11MasterKeyShare masterKeyShare = (DistributedABECPWat11MasterKeyShare) mks;

        if (attributes.size() > pp.getN()) {
            throw new IllegalArgumentException(
                    "attribute size cannot be greater than " + pp.getN() + ", but is " + attributes.size());
        }

        int serverID = masterKeyShare.getServerID();
        ZpElement u_xi = zp.getUniformlyRandomUnit();
        log.debug("Generating key share for serverID: " + serverID + " and KeyIndex:" + attributes);
        log.debug("Found u_serverID: " + u_xi);

        GroupElement D_prime_xi = pp.getG();
        D_prime_xi = D_prime_xi.pow(masterKeyShare.getShare());
        D_prime_xi = D_prime_xi.op(pp.getgA().pow(u_xi));
        log.debug("Calculated D'_serverID := g^tmp_serverID * g_a^u_serverID:" + D_prime_xi);

        GroupElement D_two_prime_xi = pp.getG().pow(u_xi);
        log.debug("Caluclated D''_serverID := g^u_serverID: " + D_two_prime_xi);

        Map<Attribute, GroupElement> D_xi = new HashMap<>();
        for (Attribute i : attributes) {
            // T(i)^x_u_i

            GroupElement D_i = (GroupElement) pp.getHashToG1().hashIntoStructure(i);
            D_i = D_i.pow(u_xi);

            D_xi.put(i, D_i);
        }

        return new DistributedABECPWat11KeyShare(D_prime_xi, D_two_prime_xi, masterKeyShare
                .getServerID(), D_xi, attributes);
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
    public Representation getRepresentation() {
        return pp.getRepresentation();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof DistributedABECPWat11) {
            DistributedABECPWat11 other = (DistributedABECPWat11) obj;
            return pp.equals(other.pp);
        } else {
            return false;
        }
    }

    @Override
    public KeyShare getKeyShare(Representation repr) {
        return new DistributedABECPWat11KeyShare(repr, pp);
    }

    @Override
    public MasterKeyShare getMasterKeyShare(Representation repr) {
        return new DistributedABECPWat11MasterKeyShare(repr);
    }

    @Override
    public int getServerCount() {
        return pp.getlMax();
    }

    @Override
    public int getMinAmountToRecreate() {
        return pp.getThreshold();
    }

}
