package de.upb.crypto.craco.ser.standalone.test.classes;

import de.upb.crypto.craco.interfaces.abe.Attribute;
import de.upb.crypto.craco.interfaces.abe.StringAttribute;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.secretsharing.SecretSharingSchemeProvider;
import de.upb.crypto.craco.secretsharing.ShamirSecretSharingSchemeProvider;
import de.upb.crypto.craco.secretsharing.ThresholdTreeSecretSharing;
import de.upb.crypto.craco.ser.standalone.test.StandaloneTestParams;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

public class ThresholdTreeSecretSharingParams {
    public static StandaloneTestParams get() {
        Attribute[] attributes = {new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")};
        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);
        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);

        ThresholdPolicy root = new ThresholdPolicy(2, leftNode, rightNode);
        Zp zp = new Zp(BigInteger.valueOf(13));
        SecretSharingSchemeProvider lsssProvider = new ShamirSecretSharingSchemeProvider();

        return new StandaloneTestParams(ThresholdTreeSecretSharing.class,
                new ThresholdTreeSecretSharing(root, zp, lsssProvider));
    }
}
