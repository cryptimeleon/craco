package de.upb.crypto.craco.abe.interfaces.distributed;

import de.upb.crypto.craco.common.interfaces.DecryptionKey;
import de.upb.crypto.craco.common.interfaces.EncryptionScheme;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.math.serialization.Representation;

import java.util.List;

/**
 * Interface for distributed encryption schemes.
 * <p>
 * The idea is that the {@link de.upb.crypto.craco.common.interfaces.pe.MasterSecret} is divided into L
 * {@link MasterKeyShare}. These Shares are distributed over L servers.
 * <p>
 * A KeyShare is generated out of a MasterKeyShare.
 * <p>
 * T out of L KeyShares are needed in order to successfully recreate a
 * DecryptionKey that can be used in an Encryption Scheme.
 *
 *
 */
public interface DistributedEncryptionScheme extends EncryptionScheme {

    public int getServerCount();

    public int getMinAmountToRecreate();

    public boolean shareVerify(KeyShare keyShare);

    /**
     * Combines a list of {@link KeyShare} to a {@link DecryptionKey}. The scheme needs a
     * specific amount of {@link KeyShare} in order to successfully create a
     * {@link DecryptionKey}.
     *
     * @param keyShares the key shares to use to construct the decryption key
     * @return the resulting decryption key
     */
    public DecryptionKey combineKeyShares(List<KeyShare> keyShares);

    public KeyShare generateKeyShare(MasterKeyShare masterKeyShare, KeyIndex keyData);

    public KeyShare getKeyShare(Representation repr);

    public MasterKeyShare getMasterKeyShare(Representation repr);

}
