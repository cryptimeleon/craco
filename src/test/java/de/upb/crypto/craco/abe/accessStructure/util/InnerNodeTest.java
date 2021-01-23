package de.upb.crypto.craco.abe.accessStructure.util;

import de.upb.crypto.craco.abe.accessStructure.exception.WrongAccessStructureException;
import de.upb.crypto.craco.abe.interfaces.RingElementAttribute;
import de.upb.crypto.craco.abe.interfaces.StringAttribute;
import de.upb.crypto.craco.common.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.rings.zn.Zn;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class InnerNodeTest {

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testStringAttriubteTreeRepresentation() {
        /**
         * Threshold tree under test:
         * (A or B ) or (C and D and E) or F
         */
        ThresholdPolicy policyA = new ThresholdPolicy(1, new StringAttribute("A"));
        ThresholdPolicy policyB = new ThresholdPolicy(1, new StringAttribute("B"));
        // a 'or' b
        ThresholdPolicy firstPolicyStmt = new ThresholdPolicy(1, policyA, policyB);

        ThresholdPolicy policyC = new ThresholdPolicy(1, new StringAttribute("C"));
        ThresholdPolicy policyD = new ThresholdPolicy(1, new StringAttribute("D"));
        ThresholdPolicy policyE = new ThresholdPolicy(1, new StringAttribute("E"));
        // threshold = 3 = 3-nary and
        ThresholdPolicy secondPolicyStmt = new ThresholdPolicy(3, policyC, policyD, policyE);

        ThresholdPolicy thirdStatement = new ThresholdPolicy(1, new StringAttribute("F"));

        //root 1 = 'or'
        ThresholdPolicy policy = new ThresholdPolicy(1, firstPolicyStmt, secondPolicyStmt, thirdStatement);

        InnerNode root = (InnerNode) new PolicyToTreeNodeConverter(policy).getTree();

        ToStringVisitor visitor = new ToStringVisitor();

        try {
            root.performVisitor(visitor);
            System.out.println(visitor.getResultOfCurrentNode());
        } catch (WrongAccessStructureException e) {
            fail("Threshold Tree malformed");
        }

        Representation rootRep = policy.getRepresentation();
        InnerNode root2 = (InnerNode) new PolicyToTreeNodeConverter(new ThresholdPolicy(rootRep)).getTree();

        ToStringVisitor visitor2 = new ToStringVisitor();
        try {
            root2.performVisitor(visitor2);
            System.out.println(visitor2.getResultOfCurrentNode());

            assertTrue("", visitor2.getResultOfCurrentNode().equals(visitor.getResultOfCurrentNode()));


        } catch (WrongAccessStructureException e) {
            fail("Threshold Tree malformed");
        }


    }

    @Test
    public void testRingElementAttributeTreeRepresentation() {
        /**
         * Threshold tree under test:
         * (A or B ) or (C and D and E) or F
         */

        // begin A or B
        InnerNode firstStmt = new InnerNode();
        firstStmt.setThreshold(1); // A "or" B

        Zn zn = new Zn(new BigInteger("42"));

        ThresholdPolicy policyA =
                new ThresholdPolicy(1, new RingElementAttribute(zn.createZnElement(new BigInteger("1"))));
        ThresholdPolicy policyB =
                new ThresholdPolicy(1, new RingElementAttribute(zn.createZnElement(new BigInteger("2"))));
        // a 'or' b
        ThresholdPolicy firstPolicyStmt = new ThresholdPolicy(1, policyA, policyB);

        ThresholdPolicy policyC =
                new ThresholdPolicy(1, new RingElementAttribute(zn.createZnElement(new BigInteger("3"))));
        ThresholdPolicy policyD =
                new ThresholdPolicy(1, new RingElementAttribute(zn.createZnElement(new BigInteger("4"))));
        ThresholdPolicy policyE =
                new ThresholdPolicy(1, new RingElementAttribute(zn.createZnElement(new BigInteger("5"))));
        // threshold = 3 = 3-nary and
        ThresholdPolicy secondPolicyStmt = new ThresholdPolicy(3, policyC, policyD, policyE);

        ThresholdPolicy thirdStatement =
                new ThresholdPolicy(1, new RingElementAttribute(zn.createZnElement(new BigInteger("6"))));

        //root 1 = 'or'
        ThresholdPolicy policy = new ThresholdPolicy(1, firstPolicyStmt, secondPolicyStmt, thirdStatement);

        InnerNode root = (InnerNode) new PolicyToTreeNodeConverter(policy).getTree();

        ToStringVisitor visitor = new ToStringVisitor();
        try {
            root.performVisitor(visitor);
            System.out.println(visitor.getResultOfCurrentNode());
        } catch (WrongAccessStructureException e) {
            fail("Threshold Tree malformed");
        }

        Representation rootRep = policy.getRepresentation();
        InnerNode root2 = (InnerNode) new PolicyToTreeNodeConverter(new ThresholdPolicy(rootRep)).getTree();

        ToStringVisitor visitor2 = new ToStringVisitor();
        try {
            root2.performVisitor(visitor2);
            System.out.println(visitor2.getResultOfCurrentNode());

            assertTrue("", visitor2.getResultOfCurrentNode().equals(visitor.getResultOfCurrentNode()));

        } catch (WrongAccessStructureException e) {
            fail("Threshold Tree malformed");
        }

    }

}
