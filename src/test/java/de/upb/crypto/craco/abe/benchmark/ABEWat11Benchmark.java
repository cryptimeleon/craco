package de.upb.crypto.craco.abe.benchmark;

import de.upb.crypto.craco.abe.cp.large.ABECPWat11;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11PublicParameters;
import de.upb.crypto.craco.abe.cp.large.ABECPWat11Setup;
import de.upb.crypto.craco.common.GroupElementPlainText;
import de.upb.crypto.craco.interfaces.CipherText;
import de.upb.crypto.craco.interfaces.DecryptionKey;
import de.upb.crypto.craco.interfaces.abe.BigIntegerAttribute;
import de.upb.crypto.craco.interfaces.abe.SetOfAttributes;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;
import de.upb.crypto.math.structures.zn.Zp.ZpElement;

/**
 * This benchmarks the key generation, encryption, decryption, and total time
 * for the large universe construction of {@link ABECPWat11}}
 * <p>
 * [Wat11] Brent Waters. Ciphertext-policy attribute-based encryption: An
 * expressive, efficient, and provably secure realization. In Public Key
 * Cryptography, pages 53–70. Springer, 2011
 *
 * @author feidens
 */
public class ABEWat11Benchmark {

    public static void main(String args[]) {
        long startTime;
        long endTime;
        long keygenTime = 0;
        long encTime = 0;
        long decTime = 0;
        long totalTime = 0;
        long negTime = 0;
        long invTime = 0;
        SetOfAttributes validAttributes = new SetOfAttributes();

        for (int i = 0; i < 100; i++) {
            BigIntegerAttribute att = new BigIntegerAttribute(i);
            validAttributes.add(att);
        }

//		StringAttribute[] attributes = new StringAttribute[] { new StringAttribute("ONE"), new StringAttribute("TWO"),
//				new StringAttribute("THREE"), new StringAttribute("FOUR") };
        Policy cind = new ThresholdPolicy(validAttributes.size(), validAttributes);
//		ThresholdPolicy leftNode = new ThresholdPolicy(1, attributes[0], attributes[2]);
//		ThresholdPolicy rightNode = new ThresholdPolicy(1, attributes[1], attributes[3]);
//		Policy cind = new ThresholdPolicy(2, leftNode, rightNode);


        // cp abe
        ABECPWat11Setup cpSetup = new ABECPWat11Setup();
        cpSetup.doKeyGenRandomOracle(60);

        ABECPWat11PublicParameters pp = cpSetup.getPublicParameters();

        Zp zp = new Zp(pp.getGroupG1().size());
        ZpElement a = zp.getUniformlyRandomElement();
        ZpElement aneg = a.neg();
        GroupElement g = pp.getGroupG1().getUniformlyRandomNonNeutral();
        GroupElement inv = g.pow(a).inv();
        GroupElement powneg = g.pow(aneg);

        ABECPWat11 cpabe = new ABECPWat11(pp);
        int runs = 10;
        for (int i = 0; i < runs; i++) {
            System.out.println("------------------------------------------------------------");

            // Benchmark start
            startTime = System.currentTimeMillis();
            //
            GroupElement powneg1 = g.pow(aneg.neg());
            // Benchmark stop
            endTime = System.currentTimeMillis();
            negTime += (endTime - startTime);
//			System.out.println("POW NEG: " + (endTime - startTime) + "ms");
            //
            // Benchmark start
            startTime = System.currentTimeMillis();
            //
            GroupElement inv1 = g.pow(a).inv();
            // Benchmark stop
            endTime = System.currentTimeMillis();
            invTime += (endTime - startTime);
//			System.out.println("POW INV: " + (endTime - startTime) + "ms");
            //

            // Benchmark start
            long compStartTime = System.currentTimeMillis();
            //
            GroupElement randomMsg = pp.getGroupGT().getUniformlyRandomNonNeutral();
            // Benchmark start
            startTime = System.currentTimeMillis();
            //
            DecryptionKey privateKey = cpabe.generateDecryptionKey(cpSetup.getMasterSecret(), validAttributes);
            // Benchmark stop
            endTime = System.currentTimeMillis();
            keygenTime += (endTime - startTime);
            System.out.println("KEY GEN: Total execution time: " + (endTime - startTime) + "ms");
            //

            GroupElementPlainText msg = new GroupElementPlainText(randomMsg);

            // Benchmark start
            startTime = System.currentTimeMillis();
            //
            CipherText ciphertext = cpabe.encrypt(msg, cind);
            // Benchmark stop
            endTime = System.currentTimeMillis();
            encTime += (endTime - startTime);
            System.out.println("ENC: Total execution time: " + (endTime - startTime) + "ms");
            //

            // Benchmark start
            startTime = System.currentTimeMillis();
            //
            GroupElementPlainText msgprime = cpabe.decrypt(ciphertext, privateKey);
            // Benchmark stop
            endTime = System.currentTimeMillis();
            decTime += (endTime - startTime);
            System.out.println("DEC: Total execution time: " + (endTime - startTime) + "ms");
            //

            // Benchmark stop
            totalTime += (endTime - compStartTime);
            System.out.println("TOTAL: Total execution time: " + (endTime - compStartTime) + "ms");
            //
            System.out.println(msg.equals(msgprime));
        }
        System.out.println("------------------------------------------------------------");
        System.out.println("------------------------------------------------------------");
        System.out.println("POW NEG: " + negTime / runs);
        System.out.println("POW INV: " + invTime / runs);
        System.out.println("------------------------------------------------------------");
        System.out.println("KEYGEN avg: " + keygenTime / runs);
        System.out.println("ENC avg: " + encTime / runs);
        System.out.println("DEC avg: " + decTime / runs);
        System.out.println("TOTAL avg: " + totalTime / runs);
    }
}
