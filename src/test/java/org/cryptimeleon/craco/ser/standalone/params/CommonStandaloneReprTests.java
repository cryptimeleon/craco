package org.cryptimeleon.craco.ser.standalone.params;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.common.attributes.*;
import org.cryptimeleon.craco.common.policies.BooleanPolicy;
import org.cryptimeleon.craco.common.policies.ThresholdPolicy;
import org.cryptimeleon.craco.secretsharing.SecretSharingSchemeProvider;
import org.cryptimeleon.craco.secretsharing.ThresholdTreeSecretSharing;
import org.cryptimeleon.craco.secretsharing.shamir.ShamirSecretSharingSchemeProvider;
import org.cryptimeleon.craco.ser.standalone.StandaloneReprSubTest;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.math.BigInteger;

public class CommonStandaloneReprTests extends StandaloneReprSubTest {
    private final Attribute[] attributes = {
            new StringAttribute("A"), new StringAttribute("B"), new StringAttribute("C"),
            new StringAttribute("D"), new StringAttribute("E")
    };
    private final ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[1]);
    private final ThresholdPolicy rightNode = new ThresholdPolicy(2, attributes[2], attributes[3], attributes[4]);
    private final ThresholdPolicy root = new ThresholdPolicy(2, leftNode, rightNode);
    private final Zp zp = new Zp(BigInteger.valueOf(13));

    public void policyTest() {
        test(root);
        test(new BooleanPolicy(BooleanPolicy.BooleanOperator.AND, new StringAttribute("A"),
                new StringAttribute("B")));
    }

    public void attributeTest() {
        test(new StringAttribute("A"));
        test(new BigIntegerAttribute(5));
        test(new ByteArrayImplementation("THISISATESTSTRING".getBytes()));
        test(new RingElementAttribute(zp.getUniformlyRandomElement()));

        StringAttribute one = new StringAttribute("one");
        StringAttribute two = new StringAttribute("two");
        StringAttribute three = new StringAttribute("three");
        test(new SetOfAttributes(one, two, three));
    }

    public void secretSharingTest() {
        SecretSharingSchemeProvider lsssProvider = new ShamirSecretSharingSchemeProvider();
        test(new ThresholdTreeSecretSharing(root, zp, lsssProvider));
    }
}
