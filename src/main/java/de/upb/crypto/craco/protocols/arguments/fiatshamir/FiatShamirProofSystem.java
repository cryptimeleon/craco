package de.upb.crypto.craco.protocols.arguments.fiatshamir;

import de.upb.crypto.craco.protocols.CommonInput;
import de.upb.crypto.craco.protocols.SecretInput;
import de.upb.crypto.craco.protocols.arguments.sigma.*;
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

    public FiatShamirProof createProof(CommonInput commonInput, SecretInput secretInput) {
        AnnouncementSecret announcementSecret = protocol.generateAnnouncementSecret(commonInput, secretInput);
        Announcement announcement = protocol.generateAnnouncement(commonInput, secretInput, announcementSecret);
        Challenge challenge = computeChallengeForAnnouncement(commonInput, announcement);
        Response response = protocol.generateResponse(commonInput, secretInput, announcement, announcementSecret, challenge);

        return new FiatShamirProof(protocol.compressTranscript(commonInput, new SigmaProtocolTranscript(announcement, challenge, response)));
    }

    public boolean checkProof(CommonInput commonInput, FiatShamirProof proof) {
        SigmaProtocolTranscript transcript = protocol.decompressTranscript(commonInput, proof.compressedTranscript);
        return computeChallengeForAnnouncement(commonInput, transcript.getAnnouncement()).equals(transcript.getChallenge());
    }

    private Challenge computeChallengeForAnnouncement(CommonInput commonInput, Announcement announcement) {
        return protocol.createChallengeFromBytes(commonInput, hash.hash(announcement));
    }
}
