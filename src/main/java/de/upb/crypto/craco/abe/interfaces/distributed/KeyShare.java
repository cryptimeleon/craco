package de.upb.crypto.craco.abe.interfaces.distributed;

import de.upb.crypto.craco.common.interfaces.pe.KeyIndex;
import de.upb.crypto.math.serialization.Representable;

public interface KeyShare extends Representable {

    public int getServerID();

    public KeyIndex getKeyIndex();
}
