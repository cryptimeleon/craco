package de.upb.crypto.craco.common.interfaces;

import de.upb.crypto.craco.abe.interfaces.distributed.KeyShare;
import de.upb.crypto.craco.abe.interfaces.distributed.MasterKeyShare;
import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.math.serialization.Representation;

import java.util.List;

/**
 * Interface for distributed crypto schemes.
 * <p>
 * The idea is that the {@link MasterKey} is divided into L
 * {@link MasterKeyShare}. These Shares are distributed over L servers.
 * <p>
 * A KeyShare is generated out of a MasterKeyShare.
 * <p>
 * T out of L KeyShares are needed in order to successfully recreate a
 * DecryptionKey that can be used in an Encryption Scheme.
 *
 * @author Marius Dransfeld, refactoring: Mirko Jürgens
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
     * @param keyShares
     * @return
     */
    public DecryptionKey combineKeyShares(List<KeyShare> keyShares);

    public KeyShare generateKeyShare(MasterKeyShare masterKeyShare, KeyIndex keyData);

    public KeyShare getKeyShare(Representation repr);

    public MasterKeyShare getMasterKeyShare(Representation repr);

}
