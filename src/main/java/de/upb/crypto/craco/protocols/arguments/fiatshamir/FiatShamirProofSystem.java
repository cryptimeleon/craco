package de.upb.crypto.craco.protocols.arguments.fiatshamir;

import de.upb.crypto.craco.protocols.CommonInput;
import de.upb.crypto.craco.protocols.SecretInput;
import de.upb.crypto.craco.protocols.arguments.sigma.*;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.hash.impl.HashAccumulator;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.interfaces.hash.HashFunction;

public class FiatShamirProofSystem {
    private final SigmaProtocol protocol;
    private final HashFunction hash;

    public FiatShamirProofSystem(SigmaProtocol protocol, HashFunction hashFunction) {
        this.protocol = protocol;
        this.hash = hashFunction;
    }

    public FiatShamirProofSystem(SigmaProtocol protocol) {
        this(protocol, new VariableOutputLengthHashFunction(protocol.getChallengeSpaceSize().bitLength()));
    }

    public FiatShamirProof createProof(CommonInput commonInput, SecretInput secretInput, byte[] additionalData) {
        AnnouncementSecret announcementSecret = protocol.generateAnnouncementSecret(commonInput, secretInput);
        Announcement announcement = protocol.generateAnnouncement(commonInput, secretInput, announcementSecret);
        Challenge challenge = computeChallengeForAnnouncement(commonInput, announcement, additionalData);
        Response response = protocol.generateResponse(commonInput, secretInput, announcement, announcementSecret, challenge);

        return new FiatShamirProof(protocol.compressTranscript(commonInput, new SigmaProtocolTranscript(announcement, challenge, response)), additionalData);
    }

    public FiatShamirProof createProof(CommonInput commonInput, SecretInput secretInput) {
        return createProof(commonInput, secretInput, new byte[0]);
    }

    public boolean checkProof(CommonInput commonInput, FiatShamirProof proof, byte[] additionalData) {
        SigmaProtocolTranscript transcript = protocol.decompressTranscript(commonInput, proof.compressedTranscript);
        return computeChallengeForAnnouncement(commonInput, transcript.getAnnouncement(), additionalData).equals(transcript.getChallenge());
    }

    public boolean checkProof(CommonInput commonInput, FiatShamirProof proof) {
        return checkProof(commonInput, proof, new byte[0]);
    }

    private Challenge computeChallengeForAnnouncement(CommonInput commonInput, Announcement announcement, byte[] additionalData) {
        ByteArrayAccumulator acc = new ByteArrayAccumulator();
        acc.escapeAndSeparate(announcement);
        acc.append(additionalData);
        return protocol.createChallengeFromBytes(commonInput, hash.hash(acc.extractBytes()));
    }
}
