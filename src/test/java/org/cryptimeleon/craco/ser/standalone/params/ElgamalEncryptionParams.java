package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.enc.asym.elgamal.ElgamalEncryption;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.math.BigInteger;

public class ElgamalEncryptionParams {

    public static StandaloneTestParams get() {
        Zp zp = new Zp(BigInteger.valueOf(72973));
        Group zpGroup = zp.asUnitGroup();
        ElgamalEncryption scheme = new ElgamalEncryption(zpGroup);
        return new StandaloneTestParams(ElgamalEncryption.class, scheme);
    }
}
