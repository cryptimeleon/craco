package de.upb.crypto.craco.commitment.pedersen;

import de.upb.crypto.craco.commitment.interfaces.CommitmentSchemePublicParametersGen;
import de.upb.crypto.math.factory.BilinearGroup;
import de.upb.crypto.math.factory.BilinearGroupFactory;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;

/**
 * This class provides a java implementation for the setup()-method of the {@link PedersenCommitmentScheme}. It
 * realizes the general {@link CommitmentSchemePublicParametersGen} interface.
 * Furthermore, it provides a specific setup()-method taking a {@link Group} as input.
 */
public class PedersenCommitmentSchemePublicParametersGen implements CommitmentSchemePublicParametersGen {

    /**
     * Calls to {@link #setup(int, int, boolean)} where <code>debugParameter</code> is <code>false</code>.
     *
     * @param lambda           security parameter
     * @param numberOfMessages the number of messages
     * @return generates an object of type {@link PedersenPublicParameters}
     */
    @Override
    public PedersenPublicParameters setup(int lambda, int numberOfMessages) {
        return setup(lambda, numberOfMessages, false);
    }

    /**
     * This method generates {@link PedersenPublicParameters}. Therefore it generates a {@link Group} and calls
     * {@link #setup(Group, int)}.
     *
     * @param lambda           security parameter  for group generation
     * @param numberOfMessages the number of messages supported in the {@link PedersenCommitmentScheme}
     * @param debugParameter   debug parameter for group generation
     * @return generates an object of type {@link PedersenPublicParameters}
     */
    public PedersenPublicParameters setup(int lambda, int numberOfMessages, boolean debugParameter) {
        Group group = generateGroup(lambda, debugParameter);
        return setup(group, numberOfMessages);
    }

    /**
     * This method generates {@link PedersenPublicParameters} taking a {@link Group} and the number of messages for
     * the {@link PedersenCommitmentScheme}as input.
     *
     * @param group            group used for {@link PedersenCommitmentScheme}
     * @param numberOfMessages the number of messages supported in the {@link PedersenCommitmentScheme}
     * @return generates an object of type {@link PedersenPublicParameters}
     */
    public PedersenPublicParameters setup(Group group, int numberOfMessages) {
        // Generate public parameter
        GroupElement[] h = new GroupElement[numberOfMessages];
        GroupElement g = group.getGenerator();

        for (int i = 0; i < h.length; i++) {
            h[i] = group.getUniformlyRandomElement();
        }
        return new PedersenPublicParameters(g, h, group);
    }


    /**
     * This is a utility method for generating a group G.
     *
     * @param lambda         security parameter for group generation
     * @param debugParameter debug parameter for group generation
     * @return {@link Group}
     */
    private Group generateGroup(int lambda, boolean debugParameter) {
        BilinearGroupFactory baseFactory = new BilinearGroupFactory(lambda);
        baseFactory.setRequirements(BilinearGroup.Type.TYPE_1);
        baseFactory.setDebugMode(debugParameter);

        BilinearMap bilinearMap = baseFactory.createBilinearGroup().getBilinearMap();
        return bilinearMap.getG1();
    }
}
