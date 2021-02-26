package org.cryptimeleon.craco.protocols.arguments.sigma.schnorr;

import org.cryptimeleon.craco.protocols.arguments.sigma.Announcement;
import org.cryptimeleon.craco.protocols.arguments.sigma.AnnouncementSecret;
import org.cryptimeleon.craco.protocols.arguments.sigma.Response;
import org.cryptimeleon.craco.protocols.arguments.sigma.SigmaProtocolTranscript;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariable;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import org.cryptimeleon.math.expressions.VariableExpression;
import org.cryptimeleon.math.expressions.bool.BooleanExpression;
import org.cryptimeleon.math.expressions.bool.GroupEqualityExpr;
import org.cryptimeleon.math.expressions.group.GroupElementExpression;
import org.cryptimeleon.math.expressions.group.GroupOpExpr;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;

/**
 * Ensures that a group element equation (that can be written as) {@code homomorphicExpression(variables) = publicConstant}
 * holds.
 *
 * Use {@link LinearExponentStatementFragment} for linear equations over exponents.
 */
public class LinearStatementFragment implements SchnorrFragment {
    private GroupElementExpression homomorphicPart;
    private GroupElement target;

    /**
     * Instantiates this fragment to prove that
     * homomorphicPart(witness) = target;
     *
     * @param homomorphicPart an expression which is linear in its {@link SchnorrVariable}s.
     * @param target the desired (public) image of homomorphicPart.
     */
    public LinearStatementFragment(GroupElementExpression homomorphicPart, GroupElement target) {
        init(homomorphicPart, target);
    }

    /**
     * Instantiates this fragment to prove that
     * the given equation is fulfilled.
     *
     * @throws IllegalArgumentException if equation is not supported (i.e. framework is unable to write it as linear(variables) = constant)
     */
    public LinearStatementFragment(GroupEqualityExpr equation) throws IllegalArgumentException {
        GroupOpExpr linearized = equation.getLhs().op(equation.getRhs().inv()).linearize();
        init(linearized.getRhs(), linearized.getLhs().inv().evaluate());
    }

    private void init(GroupElementExpression homomorphicPart, GroupElement target) {
        this.homomorphicPart = homomorphicPart;
        this.target = target;

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
        return new LinearStatementAnnouncement(
                homomorphicPart.evaluate(externalRandom).compute()
        );
    }

    @Override
    public Response generateResponse(SchnorrVariableAssignment externalWitnesses, AnnouncementSecret announcementSecret, SchnorrChallenge challenge) {
        return Response.EMPTY;
    }

    @Override
    public BooleanExpression checkTranscript(Announcement announcement, SchnorrChallenge challenge, Response response, SchnorrVariableAssignment externalResponse) {
        //Check homomorphicPart(response) = announcement + c * target (additive group notation)
        return homomorphicPart.substitute(externalResponse).isEqualTo(((LinearStatementAnnouncement) announcement).announcement.op(target.pow(challenge.getChallenge())));
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(SchnorrChallenge challenge, SchnorrVariableAssignment externalRandomResponse) {
        //Take externalRandomResponse, set annoncement to the unique value that makes the transcript valid.
        GroupElement announcement = homomorphicPart.evaluate(externalRandomResponse).op(target.pow(challenge.getChallenge().negate())).compute();

        return new SigmaProtocolTranscript(new LinearStatementAnnouncement(announcement), challenge, Response.EMPTY);
    }

    @Override
    public Announcement recreateAnnouncement(Representation repr) {
        return new LinearStatementAnnouncement(target.getStructure().restoreElement(repr));
    }

    @Override
    public Response recreateResponse(Announcement announcement, Representation repr) {
        return Response.EMPTY;
    }

    public static final class LinearStatementAnnouncement implements Announcement {
        public final GroupElement announcement;

        public LinearStatementAnnouncement(GroupElement announcement) {
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
