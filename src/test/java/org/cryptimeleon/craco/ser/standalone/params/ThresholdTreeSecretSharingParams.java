package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.attributes.Attribute;
import org.cryptimeleon.craco.common.attributes.StringAttribute;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.secretsharing.SecretSharingSchemeProvider;
import org.cryptimeleon.craco.secretsharing.ThresholdTreeSecretSharing;
import org.cryptimeleon.craco.secretsharing.shamir.ShamirSecretSharingSchemeProvider;
import org.cryptimeleon.craco.ser.standalone.StandaloneTestParams;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.math.BigInteger;

public class ThresholdTreeSecretSharingParams {
    public static StandaloneTestParams get() {
        Attribute[] attributes = {
                new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
                new StringAttribute("D"), new StringAttribute("E")
        };
        ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);
        ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);

        ThresholdPolicy root = new ThresholdPolicy(2, leftNode, rightNode);
        Zp zp = new Zp(BigInteger.valueOf(13));
        SecretSharingSchemeProvider lsssProvider = new ShamirSecretSharingSchemeProvider();

        return new StandaloneTestParams(ThresholdTreeSecretSharing.class,
                new ThresholdTreeSecretSharing(root, zp, lsssProvider));
    }
}
