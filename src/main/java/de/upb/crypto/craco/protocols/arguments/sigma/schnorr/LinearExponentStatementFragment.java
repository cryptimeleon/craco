package de.upb.crypto.craco.protocols.arguments.sigma.schnorr;

import de.upb.crypto.craco.protocols.arguments.sigma.Announcement;
import de.upb.crypto.craco.protocols.arguments.sigma.AnnouncementSecret;
import de.upb.crypto.craco.protocols.arguments.sigma.Response;
import de.upb.crypto.craco.protocols.arguments.sigma.SigmaProtocolTranscript;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariable;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.math.expressions.VariableExpression;
import de.upb.crypto.math.expressions.bool.ExponentEqualityExpr;
import de.upb.crypto.math.expressions.exponent.ExponentExpr;
import de.upb.crypto.math.expressions.exponent.ExponentSumExpr;
import de.upb.crypto.math.hash.ByteAccumulator;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.rings.zn.Zn;

/**
 * Ensures that a equation on exponents (that can be written as) {@code linearExpression(variables) = publicConstant}
 * holds.
 *
 * Use {@link LinearExponentStatementFragment} for linear equations over group elements (which is much more common).
 */
public class LinearExponentStatementFragment implements SchnorrFragment {
    private ExponentExpr homomorphicPart;
    private Zn.ZnElement target;
    private Zn zn;

    /**
     * Instantiates this fragment to prove that
     * homomorphicPart(witness) = target;
     *
     * @param homomorphicPart an expression which is linear in its variables.
     * @param target the desired (public) image of homomorphicPart.
     */
    public LinearExponentStatementFragment(ExponentExpr homomorphicPart, Zn.ZnElement target) {
        init(homomorphicPart, target);
    }

    /**
     * Instantiates this fragment to prove that
     * the equation is fulfilled.
     *
     * @throws IllegalArgumentException if equation is not supported (i.e. framework is unable to write it as linear(witnesses) = constant)
     */
    public LinearExponentStatementFragment(ExponentEqualityExpr equation, Zn zn) throws IllegalArgumentException {
        ExponentSumExpr linearized = equation.getLhs().sub(equation.getRhs()).linearize();
        init(linearized.getRhs(), linearized.getLhs().negate().evaluate(zn));
    }

    private void init(ExponentExpr homomorphicPart, Zn.ZnElement target) {
        this.homomorphicPart = homomorphicPart;
        this.target = target;
        this.zn = target.getStructure();

        homomorphicPart.treeWalk(expr -> {
            if (expr instanceof VariableExpression && !(expr instanceof SchnorrVariable))
                throw new IllegalArgumentException("Expressions must not contain non-Schnorr variables like "+expr.getClass()+" - "+expr.toString());
        });
    }

    @Override
    public AnnouncementSecret generateAnnouncementSecret(SchnorrVariableAssignment externalWitnesses) {
        return AnnouncementSecret.EMPTY;
    }

    @Override
    public Announcement generateAnnouncement(SchnorrVariableAssignment externalWitnesses, AnnouncementSecret announcementSecret, SchnorrVariableAssignment externalRandom) {
        //Evaluate homomorphicPart with respect random variable assignements from the AnnouncementSecret and the random assignments coming from the outside.
        return new LinearExponentStatementAnnouncement(
                homomorphicPart.evaluate(zn, externalRandom)
        );
    }

    @Override
    public Response generateResponse(SchnorrVariableAssignment externalWitnesses, AnnouncementSecret announcementSecret, SchnorrChallenge challenge) {
        return Response.EMPTY;
    }

    @Override
    public boolean checkTranscript(Announcement announcement, SchnorrChallenge challenge, Response response, SchnorrVariableAssignment externalResponse) {
        //Check homomorphicPart(response) = announcement + c * target (additive group notation)
        Zn.ZnElement evaluatedResponse = homomorphicPart.evaluate(zn, externalResponse);

        return evaluatedResponse.equals(((LinearExponentStatementAnnouncement) announcement).announcement.add(target.mul(challenge.getChallenge())));
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(SchnorrChallenge challenge, SchnorrVariableAssignment externalRandomResponse) {
        //Take externalRandomResponse, set annoncement to the unique value that makes the transcript valid.
        Zn.ZnElement announcement = homomorphicPart.evaluate(zn, externalRandomResponse).sub(target.mul(challenge.getChallenge()));

        return new SigmaProtocolTranscript(new LinearExponentStatementAnnouncement(announcement), challenge, Response.EMPTY);
    }

    @Override
    public Announcement recreateAnnouncement(Representation repr) {
        return new LinearExponentStatementAnnouncement(zn.getElement(repr));
    }

    @Override
    public Response recreateResponse(Announcement announcement, Representation repr) {
        return Response.EMPTY;
    }

    public static final class LinearExponentStatementAnnouncement implements Announcement {
        public final Zn.ZnElement announcement;

        public LinearExponentStatementAnnouncement(Zn.ZnElement announcement) {
            this.announcement = announcement;
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            accumulator.append(announcement);
            return accumulator;
        }

        @Override
        public Representation getRepresentation() {
            return announcement.getRepresentation();
        }
    }

    @Override
    public Representation compressTranscript(Announcement announcement, SchnorrChallenge challenge, Response response, SchnorrVariableAssignment externalResponse) {
        return response.getRepresentation(); //don't need announcement, can recompute from externalResponse later.
    }

    @Override
    public SigmaProtocolTranscript decompressTranscript(Representation compressedTranscript, SchnorrChallenge challenge, SchnorrVariableAssignment externalResponse) throws IllegalArgumentException {
        return generateSimulatedTranscript(challenge, externalResponse); //provides unique acceptable value for announcement.
    }
}
