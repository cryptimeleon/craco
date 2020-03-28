package de.upb.crypto.craco.interaction;

import java.math.BigInteger;

/**
 * @author bjoernf
 */
public abstract class KeyShare {
    /**
     * Stores the server ID
     */
    protected BigInteger serverID;

    /**
     * Returns the ID of the server corresponding to the share.
     *
     * @return ID of the server
     */
    public final BigInteger getServerID() {
        return serverID;
    }

    /**
     * Sets the ID of the server corresponding to the share
     *
     * @param serverID
     */
    public final void setServerID(BigInteger serverID) {
        this.serverID = serverID;
    }
}
