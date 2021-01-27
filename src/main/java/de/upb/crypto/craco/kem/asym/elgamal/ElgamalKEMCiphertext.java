package de.upb.crypto.craco.kem.asym.elgamal;

import de.upb.crypto.craco.enc.CipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * This class represents ciphertexts for the ElgamalKEM ElGamal based KEM.
 *
 *
 */
public class ElgamalKEMCiphertext implements CipherText {

    /**
     * The ElGamal ciphertext that encapsulates the key to encrypt the symmetric encryption key.
     */
    @Represented(restorer = "Scheme")
    private ElgamalCipherText c;

    /**
     * The encryption of the symmetric encryption key under c.
     */
    @Represented
    private ByteArrayImplementation encaps;


    public ElgamalKEMCiphertext(ElgamalCipherText c, ByteArrayImplementation encaps) {
        this.c = c;
        this.encaps = encaps;
    }

    public ElgamalKEMCiphertext(Representation repr, ElgamalEncryption scheme) {
        new ReprUtil(this).register(scheme, "Scheme").deserialize(repr);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((c == null) ? 0 : c.hashCode());
        result = prime * result + ((encaps == null) ? 0 : encaps.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ElgamalKEMCiphertext other = (ElgamalKEMCiphertext) obj;
        return Objects.equals(c, other.c)
                && Objects.equals(encaps, other.encaps);
    }

    public ElgamalCipherText getElgamalCipherText() {
        return c;
    }

    public ByteArrayImplementation getSymmetricEncryption() {
        return encaps;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
