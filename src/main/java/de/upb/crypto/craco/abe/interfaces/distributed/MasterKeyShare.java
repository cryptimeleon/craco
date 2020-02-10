package de.upb.crypto.craco.abe.interfaces.distributed;

import de.upb.crypto.math.serialization.Representable;

public interface MasterKeyShare extends Representable {

    public int getServerID();

}
