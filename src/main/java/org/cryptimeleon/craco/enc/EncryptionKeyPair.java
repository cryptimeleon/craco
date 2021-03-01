package org.cryptimeleon.craco.enc;

/**
 * A container for a pair of {@link EncryptionKey} and {@link DecryptionKey}.
 *
 *
 */
public class EncryptionKeyPair {

    private EncryptionKey pk;
    private DecryptionKey sk;

    public EncryptionKeyPair(EncryptionKey pk, DecryptionKey sk) {
        super();
        this.pk = pk;
        this.sk = sk;
    }

    public EncryptionKeyPair() {

    }

    public EncryptionKey getPk() {
        return pk;
    }

    public void setPk(EncryptionKey pk) {
        this.pk = pk;
    }

    public DecryptionKey getSk() {
        return sk;
    }

    public void setSk(DecryptionKey sk) {
        this.sk = sk;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((pk == null) ? 0 : pk.hashCode());
        result = prime * result + ((sk == null) ? 0 : sk.hashCode());
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
        EncryptionKeyPair other = (EncryptionKeyPair) obj;
        if (pk == null) {
            if (other.pk != null)
                return false;
        } else if (!pk.equals(other.pk))
            return false;
        if (sk == null) {
            if (other.sk != null)
                return false;
        } else if (!sk.equals(other.sk))
            return false;
        return true;
    }

}
