package de.upb.crypto.craco.prf.aes;

import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.prf.PrfImage;
import de.upb.crypto.craco.prf.PrfKey;
import de.upb.crypto.craco.prf.PrfPreimage;
import de.upb.crypto.craco.prf.PseudorandomFunction;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * AES as a pseudorandom function (permutation) f_k : {0,1}^l -> {0,1}^l
 * for k in {0,1}^l. Here, l is any valid AES keylength (e.g., 128, 256).
 * <p>
 * PrfKey, PrfPreimage, and PrfImage are of type ByteArrayImplementation.
 */
public class AesPseudorandomFunction implements PseudorandomFunction {
    @Represented
    protected int keylength; //length of keys in bit

    /**
     * Instantiates the PRP
     *
     * @param keylength a valid AES keylength in bit (e.g., 128 or 256)
     */
    public AesPseudorandomFunction(int keylength) {
        this.keylength = keylength;
    }

    public AesPseudorandomFunction(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public PrfKey generateKey() {
        return ByteArrayImplementation.fromRandom(keylength / 8);
    }

    @Override
    public PrfImage evaluate(PrfKey k, PrfPreimage x) {
        if (((ByteArrayImplementation) k).length() != keylength / 8)
            throw new IllegalArgumentException("key k in the AES PRF has invalid length");
        if (((ByteArrayImplementation) x).length() != keylength / 8)
            throw new IllegalArgumentException("preimage x in the AES PRF has invalid length");

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(((ByteArrayImplementation) k).getData(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return new ByteArrayImplementation(cipher.doFinal(((ByteArrayImplementation) x).getData()));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("Input k to AES PRF must be of valid AES key length");
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("Input x to AES PRF must be of valid AES key length");
        }
    }

    @Override
    public PrfKey getKey(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public PrfPreimage getPreimage(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public PrfImage getImage(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public int hashCode() {
        return keylength;
    }

    @Override
    public boolean equals(Object obj) {
        return obj != null
                && obj instanceof AesPseudorandomFunction
                && ((AesPseudorandomFunction) obj).keylength == keylength;
    }

}
