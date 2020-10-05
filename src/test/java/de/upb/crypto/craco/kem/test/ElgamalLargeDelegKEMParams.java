package de.upb.crypto.craco.kem.test;

import de.upb.crypto.craco.common.interfaces.KeyPair;
import de.upb.crypto.craco.common.interfaces.policy.Policy;
import de.upb.crypto.craco.kem.abe.cp.os.ElgamalLargeUniverseDelegationKEM;
import de.upb.crypto.craco.kem.abe.cp.os.LUDDecryptionKey;
import de.upb.crypto.craco.kem.abe.cp.os.LUDEncryptionKey;
import de.upb.crypto.craco.kem.abe.cp.os.LUDSetup;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static de.upb.crypto.craco.kem.test.ElgamalLargeUniverseDelegationKEMTest.*;

public class ElgamalLargeDelegKEMParams {
	public static List<KeyEncapsulationMechanismTestParams> getParams() {
		BilinearGroupFactory fac = new BilinearGroupFactory(80);
		fac.setDebugMode(true); // enable debug
		fac.setRequirements(BilinearGroup.Type.TYPE_3);
		BilinearGroup bilinearGroup = fac.createBilinearGroup();

		LUDSetup schemeFactory;
		schemeFactory = new LUDSetup();
		schemeFactory.setup(bilinearGroup, new SHA256HashFunction());
		ElgamalLargeUniverseDelegationKEM scheme = schemeFactory.getScheme();

		Policy policy = setupPolicy();

		LUDEncryptionKey encKey = scheme.generateEncryptionKey(policy);
		/*
		 * generate satifying and non-satisfying decryption keys for policy
		 */
		LUDDecryptionKey dkSatisfy = scheme.generateDecryptionKey(schemeFactory.getMasterSecretKey(), getFulfilling());
		LUDDecryptionKey dkNonSatisfy = scheme.generateDecryptionKey(schemeFactory.getMasterSecretKey(), getNonFulfilling());

		KeyPair validKeyPair = new KeyPair(encKey, dkSatisfy);
		KeyPair invalidKeyPair = new KeyPair(encKey, dkNonSatisfy);

		return Stream.of(
				new KeyEncapsulationMechanismTestParams(scheme, validKeyPair, invalidKeyPair)
		).collect(Collectors.toList());
	}
}
