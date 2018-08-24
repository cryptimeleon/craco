package de.upb.crypto.craco.interfaces.abe.distributed;

import de.upb.crypto.craco.interfaces.pe.KeyIndex;
import de.upb.crypto.math.serialization.Representable;

public interface KeyShare extends Representable {

    public int getServerID();

    public KeyIndex getKeyIndex();
}
