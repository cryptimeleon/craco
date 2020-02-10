package de.upb.crypto.craco.kem.asym.elgamal;

import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.common.interfaces.CipherText;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

/**
 * This class represents ciphertexts for the ElgamalKEM ElGamal based KEM.
 *
 * @author peter.guenther
 */
public class ElgamalKEMCiphertext implements CipherText {

    /**
     * The ElGamal ciphertext that encapsulates the key to encrypt the symmetric encryption key.
     */
    private ElgamalCipherText c;

    /**
     * The encryption of the symmetric encryption key under c.
     */
    private ByteArrayImplementation encaps;


    public ElgamalKEMCiphertext(ElgamalCipherText c, ByteArrayImplementation encaps) {
        this.c = c;
        this.encaps = encaps;
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
        if (!(obj instanceof ElgamalKEMCiphertext))
            return false;
        ElgamalKEMCiphertext other = (ElgamalKEMCiphertext) obj;
        if (c == null) {
            if (other.c != null)
                return false;
        } else if (!c.equals(other.c))
            return false;
        if (encaps == null) {
            if (other.encaps != null)
                return false;
        } else if (!encaps.equals(other.encaps))
            return false;
        return true;
    }

    public ElgamalCipherText getElgamalCipherText() {
        return c;
    }

    public ByteArrayImplementation getSymmetricEncryption() {
        return encaps;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation or = new ObjectRepresentation();
        or.put("c", c.getRepresentation());
        or.put("encaps", encaps.getRepresentation());
        return or;
    }

}
