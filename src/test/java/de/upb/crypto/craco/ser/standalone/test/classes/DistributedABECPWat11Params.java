package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.abe.cp.large.distributed.DistributedABECPWat11;
import de.upb.crypto.craco.abe.cp.large.distributed.DistributedABECPWat11Setup;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;

import java.util.ArrayList;
import java.util.Collection;

public class DistributedABECPWat11Params {
    public static Collection<StandaloneTestParams> get() {
        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();
        DistributedABECPWat11Setup setup = new DistributedABECPWat11Setup();
        setup.doKeyGen(80, 5, 4, 2, 2, true);
        toReturn.add(new StandaloneTestParams(DistributedABECPWat11.class, new DistributedABECPWat11(setup
                .getPublicParameters())));
        toReturn.add(new StandaloneTestParams(setup.getPublicParameters()));
        toReturn.add(new StandaloneTestParams(setup.getMasterKeyShares().iterator().next()));
        return toReturn;
    }
}
