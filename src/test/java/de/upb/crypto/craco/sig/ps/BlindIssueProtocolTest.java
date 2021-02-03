package de.upb.crypto.craco.sig.ps;

import de.upb.crypto.craco.common.plaintexts.MessageBlock;
import de.upb.crypto.craco.common.plaintexts.RingElementPlainText;
import de.upb.crypto.craco.protocols.arguments.damgardtechnique.DamgardTechnique;
import de.upb.crypto.craco.sig.SignatureKeyPair;
import de.upb.crypto.craco.sig.ps.*;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.cartesian.Vector;
import de.upb.crypto.math.structures.groups.counting.CountingBilinearGroup;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.rings.zn.Zn;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class BlindIssueProtocolTest {
    @Test
    public void testBlindSign() {
        //Set up the signature scheme
        BilinearGroup group = new CountingBilinearGroup(128, BilinearGroup.Type.TYPE_3);
        Zn zn = group.getZn();
        PSExtendedSignatureScheme scheme = new PSExtendedSignatureScheme(new PSPublicParameters(group));
        SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> keyPair = scheme.generateKeyPair(6);

        //Choose a message
        MessageBlock message = new Vector<>(4, 8, 15, 16, 23, 42).map(i -> new RingElementPlainText(zn.valueOf(i)), MessageBlock::new);

        //Set up the protocol (instance)
        PSBlindSignProtocol protocol = new PSBlindSignProtocol(scheme, DamgardTechnique.generateCommitmentScheme(group.getG1()));
        PSBlindSignProtocol.BlindSignProtocolInstance receiver = protocol.instantiateProtocolForReceiver(keyPair.getVerificationKey(), new PSBlindSignProtocol.ReceiverInput(message));
        PSBlindSignProtocol.BlindSignProtocolInstance signer = protocol.instantiateProtocolForSigner(keyPair.getVerificationKey(), keyPair.getSigningKey());

        //Run protocol
        protocol.runProtocolLocally(receiver, signer);

        //Check resulting signature
        PSSignature signature = receiver.getResultSignature();
        assertTrue(scheme.verify(message, signature, keyPair.getVerificationKey()));
    }
}
