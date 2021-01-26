package de.upb.crypto.craco.enc.asym.elgamal;

import de.upb.crypto.craco.common.PlainText;
import de.upb.crypto.craco.enc.AsymmetricEncryptionScheme;
import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.DecryptionKey;
import de.upb.crypto.craco.enc.EncryptionKey;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.rings.zn.Zn;
import de.upb.crypto.math.structures.rings.zn.Zn.ZnElement;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Encryption scheme originally presented by Elgamal in [1]. The key generation, encryption and decryption algorithm can
 * be described as follows:
 * <p>
 * Let G be a cyclic group of order $q$.
 * <p>
 * Key generation:
 * - Choose a \in Z_q = {0,1, ..., q-1} uniformly at random.
 * - Choose generator g of G uniformly at random.
 * - The private key is (G, g, a, h = g^a) and the public key is (G, g, h)
 * <p>
 * Encryption of message m \in G under public key pk = (G, g, h):
 * - Choose r \in Z_q uniformly at random.
 * - The ciphertext is c = (c_1, c_2) = (g^r, m * h^r)
 * <p>
 * Decryption of c = (c_1, c_2) under private key sk = (G, g, a, h):
 * - The message is m = c_2 * c_1^{-a}
 * <p>
 * <p>
 * [1] T. Elgamal, "A public key cryptosystem and a signature scheme based on discrete logarithms," in IEEE Transactions
 * on Information Theory, vol. 31, no. 4, pp. 469-472, July 1985.
 */
public class ElgamalEncryption implements AsymmetricEncryptionScheme {

    @Represented
    Group groupG;

    public ElgamalEncryption(Group groupG) {
        this.groupG = groupG;
    }

    public ElgamalEncryption(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    public Group getGroup() {
        return groupG;
    }

    @Override
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey) {
        //choose a random element random \in {0, ..., sizeG}
        BigInteger sizeG = groupG.size();

        Zn zn_random = new Zn(sizeG);
        ZnElement random_zn_element = zn_random.getUniformlyRandomElement();

        return this.encrypt(plainText, publicKey, random_zn_element.getInteger());
    }

    /**
     * Encrypt message under public key and use given randomness.
     * <p>
     * This function is used internally. Randomness is either uniform at random to obtain the standard Elgamal
     * Encryption.
     * But, e.g. for Fujisaki-Okamoto transform, the randomness is the result of mangling the message
     * with additional randomness.
     *
     * @param plainText the message to encrypt
     * @param publicKey the key to use for encryption
     * @param random the randomness to use for encryption
     * @return the encrypted message as a cipher text
     */
    public CipherText encrypt(PlainText plainText, EncryptionKey publicKey, BigInteger random) {
        if (publicKey == null || plainText == null)
            throw new IllegalArgumentException("The arguments must not be null.");
        if (!(publicKey instanceof ElgamalPublicKey))
            throw new IllegalArgumentException("The specified public key is invalid.");
        if (!(plainText instanceof ElgamalPlainText))
            throw new IllegalArgumentException("The specified plaintext is invalid.");

        GroupElement groupElementPlaintext = ((ElgamalPlainText) plainText).getPlaintext();
        GroupElement g = ((ElgamalPublicKey) publicKey).getG();
        GroupElement h = ((ElgamalPublicKey) publicKey).getH();

        //c1 = g^r
        GroupElement c1 = g.pow(random);

        //c2 = h^r * plaintext
        GroupElement c2 = h.pow(random).op(groupElementPlaintext);

        return new ElgamalCipherText(c1.compute(), c2.compute());
    }

    @Override
    public PlainText decrypt(CipherText cipherText, DecryptionKey privateKey) {
        if (privateKey == null || cipherText == null)
            throw new IllegalArgumentException("The arguments must not be null.");
        if (!(cipherText instanceof ElgamalCipherText))
            throw new IllegalArgumentException("The specified ciphertext is invalid.");
        if (!(privateKey instanceof ElgamalPrivateKey))
            throw new IllegalArgumentException("The specified private key is invalid.");

        ElgamalCipherText cpCipherText = (ElgamalCipherText) cipherText;
        ZnElement a = ((ElgamalPrivateKey) privateKey).getA();
        GroupElement u = cpCipherText.getC1().pow(a);
        GroupElement m = u.inv().op(cpCipherText.getC2());
        return new ElgamalPlainText(m.compute());
    }

    /**
     * Generates a public/private-key pair for the specified group.
     *
     * @return A pair of a private key and the corresponding public key.
     */
    @Override
    public KeyPair generateKeyPair() {
        BigInteger sizeG = groupG.size();
        //choose a random element 'a' \in {0, ..., sizeG}
        Zn zn_random = new Zn(sizeG);
        ZnElement a = zn_random.getUniformlyRandomElement();

        //choose a random generator of the group
        GroupElement generator = groupG.getUniformlyRandomNonNeutral();

        GroupElement h = generator.pow(a).compute();

        //create a elgamal private key
        ElgamalPrivateKey privateKey = new ElgamalPrivateKey(groupG, generator, a, h);

        //generate the public key (g, h)
        EncryptionKey publicKey = privateKey.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }

    @Override
    public PlainText getPlainText(Representation repr) {
        return new ElgamalPlainText(repr, groupG);
    }

    @Override
    public ElgamalCipherText getCipherText(Representation repr) {
        return new ElgamalCipherText(repr, groupG);
    }

    @Override
    public ElgamalPublicKey getEncryptionKey(Representation repr) {
        return new ElgamalPublicKey(repr);
    }

    @Override
    public ElgamalPrivateKey getDecryptionKey(Representation repr) {
        return new ElgamalPrivateKey(repr, groupG.getZn(), this);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ElgamalEncryption other = (ElgamalEncryption) o;
        return Objects.equals(groupG, other.groupG);
    }

    @Override
    public int hashCode() {
        return groupG != null ? groupG.hashCode() : 0;
    }
}
