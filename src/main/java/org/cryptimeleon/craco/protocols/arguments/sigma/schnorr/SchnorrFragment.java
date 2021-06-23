package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr;

import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import org.cryptimeleon.craco.protocols.arguments.sigma.*;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariable;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.serialization.ListRepresentation;
import org.cryptimeleon.math.serialization.Representation;

/**
 * Part of a Schnorr-style protocol, which may depend on variables (witnesses)
 * for which another protocol is in charge of ensuring extractability.
 * It is usually part of a larger composition of fragments that form a complete protocol.
 *
 * <br>
 *
 * This is motivated by the following idea: Assume we want to come up with e Schnorr-like protocol for the relation {@code {((h1,h2),w) | h1 = g1^w ∧ h2 = g2^w}},
 * meaning that the same witness {@code w} simultaneously fulfills the two equations. <br>
 * The standard Schnorr-style protocol for this works as follows:
 * <ol>
 *     <li>The prover chooses a random {@code r} and sends {@code A1 = g1^r} and {@code A2 = g2^r} to the verifier</li>
 *     <li>The verifier responds with a challenge {@code c}</li>
 *     <li>The prover responds with {@code R = c * w + r}</li>
 *     <li>The verifier checks that {@code g1^R = h1^c * A1} and {@code g2^R = h2^c * A1}</li>
 * </ol>
 * <br>
 * Thinking in fragments, we identify three parts of this protocol:
 * <ul>
 *     <li>The first fragment ensures extractability (in the sense of special soundness for {@link SigmaProtocol}s) of {@code w} by sending {@code c * w + r} as the response</li>
 *     <li>The second fragment ensures that the extracted {@code w} fulfills {@code h1 = g1^w} by sending {@code A1 = g1^r} and making the verifier check {{@code g1^R = h1^c * A1}}</li>
 *     <li>The third fragment ensures that the extracted {@code w} fulfills {@code h2 = g2^w} by sending {@code A2 = g2^r} and making the verifier check {{@code g2^R = h2^c * A2}}</li>
 * </ul>
 *
 * <p>
 *     Note that the second and third fragment share the same {@code w} and {@code r}. This dependency is expressed in this interface:
 *     a {@linkplain SchnorrFragment}'s trascript generation may depend on variables that are outside of its own control. We call those variables "external" variables.
 *
 * <p>
 *     This approach allows for easy composition of fragments that depend on (some of) the same variables.
 *     However, this also means that {@linkplain SchnorrFragment}s are basically useless by themselves because they depend on external variables.
 *     To ultimately make use of a {@linkplain SchnorrFragment} in an actual protocol, implement a {@link SendThenDelegateProtocol} and use the fragment as a subprotocol.
 *
 * <p>
 *     Implementing classes are usually used as follows:
 *     <ol>
 *         <li>The constructor is called with some data that contains and depends on external variables (e.g., an Expression like "h1 = g1^w", where w is a {@link SchnorrVariable})</li>
 *         <li>{@code generateAnnouncementSecret(externalWitnesses)} is called, where {@code externalWitnesses} is some appropriate assignment (corresponds to {@code w} in the example above)</li>
 *         <li>{@code generateAnnouncement(externalWitnesses, announcementSecret, externalRandom)} is called, where {@code externalRandom} is a random assignment of external variables (corresponds to {@code r} in the example above)</li>
 *         <li>{@code generateResponse(externalWitnesses, announcementSecret, challenge)} is called ({@code challenge} corresponds to {@code c} in the example above)</li>
 *         <li>{@code checkTranscript(announcement, challenge, response, externalResponse)} is called with the data generated above and {@code externalResponse}, which is the same as {@code externalWitness * challenge + externalRandom}</li>
 *     </ol>
 *
 *     This implementation shall be done such that the following protocol has all the properties of a {@link SigmaProtocol}:
 *     <ul>
 *         <li>Prover generates random externalRandom</li>
 *         <li>Prover sends {@code A = generateAnnouncement(externalWitnesses, announcementSecret, externalRandom)}</li>
 *         <li>Verifier sends an appropriate challenge {@code c}</li>
 *         <li>Prover sends {@code R = generateResponse(externalWitness, announcementSecret, challenge)} and {@code externalResponse = externalWitness * c + externalRandom}</li>
 *         <li>Verifier checks {@code checkTranscript(A, c, R, externalResponse)}</li>
 *     </ul>
 *     using the standard (response0-response1)/(challenge0-challenge1) knowledge extractor.
 *
 * <p>
 *     Most {@linkplain SchnorrFragment}s will probably be implemented by extending {@link DelegateFragment} or {@link SendThenDelegateFragment}.
 *     To compose a bunch of {@linkplain SchnorrFragment}s into a {@link SigmaProtocol}, see {@link DelegateProtocol} or {@link SendThenDelegateProtocol}.
 */
public interface SchnorrFragment {
    /**
     * Generates secret data that's passed in successive calls for the prover.
     * @param externalWitnesses witnesses used by this protocol whose extractability is handled outside of this fragment. May contain some variables not relevant for this fragment.
     * @return arbitrary data for future calls
     */
    AnnouncementSecret generateAnnouncementSecret(SchnorrVariableAssignment externalWitnesses);

    /**
     * Generates an announcement.
     * @param externalWitnesses witnesses used by this protocol whose extractability is handled outside of this fragment. May contain some variables not relevant for this fragment.
     * @param announcementSecret the secret generated by {@link SchnorrFragment#generateAnnouncementSecret(SchnorrVariableAssignment)}
     * @param externalRandom contains an assignment of external variables to random values.
     * @return the announcement for this fragment
     */
    Announcement generateAnnouncement(SchnorrVariableAssignment externalWitnesses, AnnouncementSecret announcementSecret, SchnorrVariableAssignment externalRandom);

    /**
     * Generates a response.
     * @param externalWitnesses witnesses used by this protocol whose extractability is handled outside of this fragment. May contain some variables not relevant for this fragment.
     * @param announcementSecret the secret generated by {@link SchnorrFragment#generateAnnouncementSecret(SchnorrVariableAssignment)}.
     * @param challenge the challenge of a Schnorr protocol.
     * @return the response that this fragment sends (does not contain externalResponse)
     */
    Response generateResponse(SchnorrVariableAssignment externalWitnesses, AnnouncementSecret announcementSecret, ZnChallenge challenge);

    /**
     * Checks whether the fragment's transcript with the addition of externalResponse is accepting.
     * @return an expression (without variables) that evaluates to true if the transcript is accepting or to false otherwise.
     */
    BooleanExpression checkTranscript(Announcement announcement, ZnChallenge challenge, Response response, SchnorrVariableAssignment externalResponse);

    /**
     * Generates a simulated transcript.
     * @param challenge challenge the transcript shall use.
     * @param externalRandomResponse a random assignment of external variables to random values.
     * @return a transcript with the same distribution as honest executions of this fragment that contain challenge and externalRandomResponse.
     */
    SigmaProtocolTranscript generateSimulatedTranscript(ZnChallenge challenge, SchnorrVariableAssignment externalRandomResponse);

    /**
     * Returns a compressed (shorter) version of the given transcript.
     * Useful for {@link FiatShamirProofSystem}.
     */
    default Representation compressTranscript(Announcement announcement, ZnChallenge challenge, Response response, SchnorrVariableAssignment externalResponse) {
        ListRepresentation repr = new ListRepresentation();
        repr.add(announcement.getRepresentation());
        repr.add(response.getRepresentation());

        return repr;
    }

    /**
     * Decompressed a transcript compressed with {@link SchnorrFragment#compressTranscript}
     *
     * The guarantee is that if a transcript is valid, then compressing and decompressing yields the same transcript.
     * Additionally, any transcript output by this method is valid (i.e. {@link SigmaProtocol#checkTranscript} returns true).
     *
     * @throws IllegalArgumentException is the given compressedTranscript cannot be decompressed into a valid transcript.
     */
    default SigmaProtocolTranscript decompressTranscript(Representation compressedTranscript, ZnChallenge challenge, SchnorrVariableAssignment externalResponse) throws IllegalArgumentException {
        Announcement announcement = restoreAnnouncement(compressedTranscript.list().get(0));
        Response response = restoreResponse(announcement, compressedTranscript.list().get(1));
        return new SigmaProtocolTranscript(announcement, challenge, response);
    }

    Announcement restoreAnnouncement(Representation repr);
    Response restoreResponse(Announcement announcement, Representation repr);
}
