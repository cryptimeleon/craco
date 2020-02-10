package de.upb.crypto.craco.abe.util;

import de.upb.crypto.craco.abe.fuzzy.large.IBEFuzzySW05;
import de.upb.crypto.craco.abe.fuzzy.large.Identity;
import de.upb.crypto.craco.abe.interfaces.BigIntegerAttribute;

import java.math.BigInteger;

/**
 * Generates three kind of identities that are used in serveral tests related to the {@link IBEFuzzySW05}
 * and relatives.
 * <p>
 * The tests are hard coded for a number of attributes of 6 and threshold of 3 (2 would work as well).
 */
public class IBEFuzzySW05TestParamGenerator {

    /**
     * @return an identity with 6 attributes that should be used for the public key's identity.
     */
    public static Identity generatePublicKeyIdentity() {
        Identity omegaPubKey = new Identity();

        omegaPubKey.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(1)));
        omegaPubKey.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(2)));
        omegaPubKey.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omegaPubKey.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omegaPubKey.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(5)));
        omegaPubKey.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(6)));

        return omegaPubKey;
    }

    /**
     * @return an identity with 6 attributes such that the size of the intersection with the identity output by
     * {@link #generatePublicKeyIdentity()} is exactly 3. This should be used for a valid secret key.
     */
    public static Identity generatePrivateKeyValidIdentity() {
        Identity omegaValid = new Identity();
        omegaValid.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(4)));
        omegaValid.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(3)));
        omegaValid.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omegaValid.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(7)));
        omegaValid.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omegaValid.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(9)));

        return omegaValid;
    }

    /**
     * @return an identity with 6 attributes such that the size of the intersection with the identity output by
     * {@link #generatePublicKeyIdentity()} is exactly 1. This should be used for a invalid secret key.
     */
    public static Identity generatePrivateKeyCorruptedIdentity() {
        Identity omegaCorrupted = new Identity();

        omegaCorrupted.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(6)));
        omegaCorrupted.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(8)));
        omegaCorrupted.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(9)));
        omegaCorrupted.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(10)));
        omegaCorrupted.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(11)));
        omegaCorrupted.addAttribute(new BigIntegerAttribute(BigInteger.valueOf(12)));

        return omegaCorrupted;
    }
}
