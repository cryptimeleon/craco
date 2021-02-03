package de.upb.crypto.craco.ser.standalone.params;

import de.upb.crypto.craco.enc.asym.elgamal.ElgamalEncryption;
import de.upb.crypto.craco.ser.standalone.StandaloneTestParams;
import de.upb.crypto.math.structures.groups.Group;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.math.BigInteger;

public class ElgamalEncryptionParams {

    public static StandaloneTestParams get() {
        Zp zp = new Zp(BigInteger.valueOf(72973));
        Group zpGroup = zp.asUnitGroup();
        ElgamalEncryption scheme = new ElgamalEncryption(zpGroup);
        return new StandaloneTestParams(ElgamalEncryption.class, scheme);
    }
}
