package de.upb.crypto.craco.abe.ibe;

import de.upb.crypto.craco.common.interfaces.*;
import de.upb.crypto.craco.common.interfaces.pe.*;
import de.upb.crypto.craco.common.utils.ByteUtil;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implementation of FullIdent scheme from "Identity-Based Encryption from the
 * Weil Pairing" by Boneh and Franklin.
 *
 * @author Marius Dransfeld, refactoring: Fabian Eidens
 */
public class FullIdent implements PredicateEncryptionScheme {

    private FullIdentPublicParameters pp;

    private SecureRandom random;

    private HashFunction hashFunction2;

    public FullIdent(FullIdentPublicParameters pp) {
        this.pp = pp;
        random = new SecureRandom();
        hashFunction2 = new SHA256HashFunction();
    }

    public FullIdent(Representation repr) {
        this.pp = new FullIdentPublicParameters(repr);
        random = new SecureRandom();
        hashFunction2 = new SHA256HashFunction();
    }

    /**
     * Hash function: {0,1}^* -> G_1
     *
     * @param data
     * @return group element
     */
    protected GroupElement H1(byte[] data) {
        return pp.getHashToG1().hash(data);
    }

    /**
     * Hash function: G_T -> {0,1}^n
     *
     * @param groupElement target group element
     * @return
     */
    private byte[] H2(GroupElement groupElement) {
        byte[] hash = hashFunction2.hash(groupElement);
        return Arrays.copyOfRange(hash, 0, pp.getN().intValue());
    }

    /**
     * Hash function: {0,1}^n x {0,1}^n -> Z_p
     *
     * @param s1
     * @param s2
     * @return
     */
    private BigInteger H3(byte[] s1, byte[] s2) {
        // ensure result < p
        int bitSize = pp.getGroupG1().size().bitLength();
        ByteAccumulator accu = new ByteArrayAccumulator();
        accu.append(s1);
        accu.append(s2);
        byte[] hash = hashFunction2.hash(accu.extractBytes());
        return new BigInteger(Arrays.copyOfRange(hash, 0, bitSize));
    }

    /**
     * Hash function {0,1}^n -> {0,1}^n
     *
     * @param s
     * @return
     */
    private byte[] H4(byte[] s) {
        return Arrays.copyOfRange(hashFunction2.hash(s), 0, pp.getN().intValue());
    }

    @Override
    public FullIdentCipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        if (!(plainText instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Not a valid plain text or this scheme");
        if (!(publicKey instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Not a valid public key for this scheme");

        ByteArrayImplementation pt = (ByteArrayImplementation) plainText;
        ByteArrayImplementation pk = (ByteArrayImplementation) publicKey;

        if (pt.getData().length != pp.getN().intValue()) {
            throw new IllegalArgumentException(
                    "plain text length should be " + pp.getN().intValue() + " bytes, but is " + pt.getData().length);
        }
        // in G1
        GroupElement Q_id = H1(pk.getData());
        // in G2
        GroupElement g_id = pp.getBilinearMap().apply(Q_id, pp.getP_pub());
        // sigma is random
        byte[] sigma = new byte[pp.getN().intValue()];

        random.nextBytes(sigma);
        // r = H_3(sigma)
        BigInteger r = H3(sigma, pt.getData());
        // U = p^r
        GroupElement U = pp.getP().pow(r);
        // V = sigma \oplus H_2(g_id^r)

        byte[] V = ByteUtil.xor(sigma, H2(g_id.pow(r)));
        // W = m \oplus H_4(sigma)

        byte[] W = ByteUtil.xor(pt.getData(), H4(sigma));
        return new FullIdentCipherText(U.compute(), V, W);
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (!(cipherText instanceof FullIdentCipherText))
            throw new IllegalArgumentException("Invalid cipher text for this scheme");
        if (!(privateKey instanceof FullIdentDecryptionKey))
            throw new IllegalArgumentException("Invalid private key for this scheme");

        FullIdentCipherText ct = (FullIdentCipherText) cipherText;
        FullIdentDecryptionKey sk = (FullIdentDecryptionKey) privateKey;

        if (ct.getV().length != pp.getN().intValue())
            throw new IllegalArgumentException(
                    "cipher text length should be " + pp.getN().intValue() + " bytes, but is " + ct.getV().length);
        if (ct.getW().length != pp.getN().intValue())
            throw new IllegalArgumentException(
                    "cipher text length should be " + pp.getN().intValue() + " bytes, but is " + ct.getW().length);

        GroupElement U = ct.getU();
        byte[] V = ct.getV();
        byte[] W = ct.getW();
        // V \oplus H2(e(d_id, U))
        byte[] sigma = ByteUtil.xor(V, H2(pp.getBilinearMap().apply(sk.getD_id(), U)));
        // W = M \oplus H_4(sigma)
        byte[] message = ByteUtil.xor(W, H4(sigma));

        BigInteger r = H3(sigma, message);

        if (!U.equals(pp.getP().pow(r)))
            throw new UnqualifiedKeyException("Decrypting failed");

        return new ByteArrayImplementation(message);
    }

    @Override
    public Representation getRepresentation() {
        return pp.getRepresentation();
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public CipherText getCipherText(Representation repr) {
        return new FullIdentCipherText(repr, pp);
    }

    @Override
    public EncryptionKey getEncryptionKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public DecryptionKey getDecryptionKey(Representation repr) {
        return new FullIdentDecryptionKey(repr, pp);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pp == null) ? 0 : pp.hashCode());
        result = prime * result + ((random == null) ? 0 : random.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        FullIdent other = (FullIdent) o;
        return Objects.equals(pp, other.pp);
    }

    @Override
    public MasterSecret getMasterSecret(Representation repr) {
        return new FullIdentMasterSecret(repr, pp);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Generates a {@link DecryptionKey} out of a given
     * {@link ByteArrayImplementation} this means that this
     * {@link DecryptionKey} can only decrypt cipher texts that are encrypted
     * with an {@link EncryptionKey} that has the same
     * {@link ByteArrayImplementation} as {@link CiphertextIndex} as this
     * {@link KeyIndex}. is the same as this one.
     */
    @Override
    public DecryptionKey generateDecryptionKey(MasterSecret msk, KeyIndex kind) {
        if (!(msk instanceof FullIdentMasterSecret))
            throw new IllegalArgumentException("Not a valid Master-Secret for this scheme");
        if (!(kind instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("Expected a ByteArrayImplementation as KeyIndex.");
        ByteArrayImplementation identity = (ByteArrayImplementation) kind;
        FullIdentMasterSecret masterSecret = (FullIdentMasterSecret) msk;
        GroupElement Q_id = H1(identity.getData());
        GroupElement d_id = Q_id.pow(masterSecret.getS());
        return new FullIdentDecryptionKey(d_id.compute());
    }

    /**
     * {@inheritDoc}
     * <p>
     * Generates a {@link EncryptionKey} out of a given
     * {@link ByteArrayImplementation} this means that all plain texts that are
     * encrypted by this {@link EncryptionKey} can only be decrypted if the
     * {@link ByteArrayImplementation} of the respective {@link DecryptionKey}
     * is the same as this one.
     */
    @Override
    public EncryptionKey generateEncryptionKey(CiphertextIndex cind) {
        if (!(cind instanceof ByteArrayImplementation))
            throw new IllegalArgumentException("ByteArrayImplementation expected as CipherTextIndex");
        return (ByteArrayImplementation) (cind);
    }

    /**
     * {@inheritDoc}
     * <p>
     * This scheme uses a {@link ByteArrayImplementation} as {@link KeyIndex}
     * and {@link CiphertextIndex}. The predicate is that the {@link KeyIndex}
     * is the same as the {@link CiphertextIndex}.
     */
    @Override
    public Predicate getPredicate() {
        return (kind, cind) -> {
            if (!(kind instanceof ByteArrayImplementation))
                throw new IllegalArgumentException("ByteArrayImplementation expected as KeyIndex");
            if (!(cind instanceof ByteArrayImplementation))
                throw new IllegalArgumentException("ByteArrayImplementation expected as CipherTextIndex");
            ByteArrayImplementation bKind = (ByteArrayImplementation) kind;
            ByteArrayImplementation bCind = (ByteArrayImplementation) cind;
            return bKind.equals(bCind);
        };
    }

    protected FullIdentPublicParameters getPublicParameters() {
        return pp;
    }
}
