package org.cryptimeleon.craco.sig.sps;

import org.cryptimeleon.craco.common.plaintexts.MessageBlock;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.craco.common.plaintexts.GroupElementPlainText;

/**
 * Interface to define a message check for SPSSchemes.
 * Provides a default implementation for schemes that simply sign a vector of group elements.
 * May be overridden for schemes with more complicated message spaces
 *
 */
public interface SPSMessageSpaceVerifier {

    /**
     * Checks if the given plainText matches the structure expected by the scheme
     *      and throws detailed exception if the plainText fails any check.
     *
     * For this default implementation, the following properties of the parameter {@param plainText} are checked:
     *      * {@param plainText} is of type {@link org.cryptimeleon.craco.common.plaintexts.MessageBlock}.
     *      * The amount of PlainTexts matches {@param expectedMessageLength}.
     *      * The elements stored in {@param plainText} are of type {@link GroupElementPlainText}.
     *      * The elements stored in said {@link GroupElementPlainText}s are \in {@param expectedGroup}
     *
     * */
    default void doMessageChecks(PlainText plainText, int expectedMessageLength, Group expectedGroup)
            throws IllegalArgumentException{

        MessageBlock messageBlock;

        // The scheme expects a MessageBlock...
        if(plainText instanceof MessageBlock) {
            messageBlock = (MessageBlock) plainText;
        }
        else {
            throw new IllegalArgumentException("The scheme requires its messages to a MessageBlock");
        }

        // ... with a size that matches the expected size...
        if(messageBlock.length() != expectedMessageLength) {
            throw new IllegalArgumentException(String.format(
                    "The scheme expected a message of length %d, but the size was: %d",
                    expectedMessageLength, messageBlock.length()
            ));
        }

        // ...where each message element...
        for (int i = 0; i < messageBlock.length(); i++) {

            // ...is a group element...
            if(!(messageBlock.get(i) instanceof GroupElementPlainText)) {
                throw new IllegalArgumentException(
                        String.format(
                                "The scheme expected its Messages to contain GroupElements," +
                                        " but element %d was of type: %s",
                                i, messageBlock.get(i).getClass().toString()
                        )
                );
            }

            // ...in the expected group.
            GroupElementPlainText group1ElementPT = (GroupElementPlainText) messageBlock.get(i);

            if(!(group1ElementPT.get().getStructure().equals(expectedGroup))) {
                throw new IllegalArgumentException(
                        String.format(
                                "The scheme expected GroupElements in %s," +
                                        " but element %d was in: %s",
                                expectedGroup.toString(),
                                i,
                                group1ElementPT.get().getStructure().toString()
                        )
                );
            }
        }

        // if no exception has been thrown at this point, we can assume the message matches the expected structure.
    }

}
