package de.upb.crypto.craco.abe.interfaces.distributed;

import de.upb.crypto.math.serialization.Representable;

/**
 * A share of a {@link de.upb.crypto.craco.common.interfaces.pe.MasterSecret}.
 * Distributed over servers.
 */
public interface MasterKeyShare extends Representable {

    public int getServerID();

}
