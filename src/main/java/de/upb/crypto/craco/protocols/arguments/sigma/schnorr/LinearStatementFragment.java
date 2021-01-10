package de.upb.crypto.craco.protocols.arguments.sigma.schnorr;

import de.upb.crypto.craco.protocols.arguments.sigma.*;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariable;
import de.upb.crypto.craco.protocols.arguments.sigma.schnorr.variables.SchnorrVariableAssignment;
import de.upb.crypto.math.expressions.VariableExpression;
import de.upb.crypto.math.expressions.bool.GroupEqualityExpr;
import de.upb.crypto.math.expressions.group.GroupElementExpression;
import de.upb.crypto.math.expressions.group.GroupOpExpr;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;

public class LinearStatementFragment implements SchnorrFragment {
    private GroupElementExpression homomorphicPart;
    private GroupElement target;

    /**
     * Instantiates this fragment to prove knowledge a witness (consisting of values for all BasicNamedExponentVariableExpr in homomorphicPart) such that
     * homomorphicPart(witness) = target;
     *
     * @param homomorphicPart an expression which is linear in its variables.
     * @param target the desired (public) image of homomorphicPart.
     */
    public LinearStatementFragment(GroupElementExpression homomorphicPart, GroupElement target) {
        init(homomorphicPart, target);
    }

    /**
     * Instantiates this fragment to prove knowledge a witness (consisting of all variables in the given equation) such that
     * the equation is fulfilled.
     *
     * @throws IllegalArgumentException if equation is not supported (i.e. framework is unable to write it as linear(witnesses) = constant)
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
                homomorphicPart.evaluate(externalRandom)
        );
    }

    @Override
    public Response generateResponse(SchnorrVariableAssignment externalWitnesses, AnnouncementSecret announcementSecret, SchnorrChallenge challenge) {
        return Response.EMPTY;
    }

    @Override
    public boolean checkTranscript(Announcement announcement, SchnorrChallenge challenge, Response response, SchnorrVariableAssignment externalResponse) {
        //Check homomorphicPart(response) = announcement + c * target (additive group notation)
        GroupElement evaluatedResponse = homomorphicPart.evaluate(externalResponse);

        return evaluatedResponse.equals(((LinearStatementAnnouncement) announcement).announcement.op(target.pow(challenge.getChallenge())));
    }

    @Override
    public SigmaProtocolTranscript generateSimulatedTranscript(SchnorrChallenge challenge, SchnorrVariableAssignment externalRandomResponse) {
        //Take externalRandomResponse, set annoncement to the unique value that makes the transcript valid.
        GroupElement announcement = homomorphicPart.evaluate(externalRandomResponse).op(target.pow(challenge.getChallenge()).inv());

        return new SigmaProtocolTranscript(new LinearStatementAnnouncement(announcement), challenge, Response.EMPTY);
    }

    @Override
    public Announcement recreateAnnouncement(Representation repr) {
        return new LinearStatementAnnouncement(target.getStructure().getElement(repr));
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
}
