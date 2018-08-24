package de.upb.crypto.craco.interfaces.abe.distributed;

import de.upb.crypto.math.serialization.Representable;

public interface MasterKeyShare extends Representable {

    public int getServerID();

}
