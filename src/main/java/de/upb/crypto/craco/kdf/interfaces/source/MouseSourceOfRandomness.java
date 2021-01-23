package de.upb.crypto.craco.kdf.interfaces.source;

import de.upb.crypto.craco.kdf.interfaces.SourceOfRandomness;
import de.upb.crypto.craco.kem.KeyMaterial;
import de.upb.crypto.math.hash.ByteAccumulator;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;

/**
 * Implements a source of randomness based on mouse movements on a panel. We
 * assume that there are 2 bits of randomness in every mouse position. However,
 * we may need some statistical tests to assert this.
 *
 * @author Mirko Jürgens
 */
public class MouseSourceOfRandomness implements SourceOfRandomness {

    private int minEntropy;

    private static final int windowWidth = 600;

    private static final int windowWidthLength = (int) Math.log10(windowWidth);

    private static final int windowHeigth = 400;

    private static final int windowHeigthLength = (int) Math.log10(windowWidth);

    private MouseMovementWindow window;

    public MouseSourceOfRandomness(int minEntropy) {
        this.minEntropy = minEntropy;
    }

    @Override
    public int getOutputLength() {
        double neededSamples = ((double) minEntropy) / 4;
        // per sample we have windowWidthLength + windowHeigthLength bytes
        // output length
        return (int) (neededSamples * (windowHeigthLength + windowWidthLength + 2) * 8);
    }

    @Override
    public int getMinEntropy() {
        return minEntropy;
    }

    @Override
    public KeyMaterial sampleElement() {
        Semaphore sem = new Semaphore(1);
        window = new MouseMovementWindow(windowWidth, windowHeigth, this, sem);
        try {
            sem.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return window.getMaterial();
    }

    public class MousePositionKeyMaterial implements KeyMaterial, Serializable {

        /**
         *
         */
        private static final long serialVersionUID = 1L;

        private List<Integer> xPositions = new ArrayList<>();

        private List<Integer> yPositions = new ArrayList<>();

        public void updatePositions(int x, int y) {
            xPositions.add(x);
            yPositions.add(y);
        }

        @Override
        public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
            for (int i = 0; i < xPositions.size(); i++) {
                int x = xPositions.get(i);
                int y = yPositions.get(i);
                accumulator.escapeAndAppend(serializeWidth(x));
                accumulator.escapeAndAppend(serializeHeight(y));
            }
            return accumulator;
        }

        private String serializeHeight(int d) {
            int length = (int) Math.log10(d);
            if (d == 0) {
                return "000";
            }
            int leadingZeroes = windowHeigthLength - length;
            StringBuilder builder = new StringBuilder(windowHeigthLength);
            for (int i = 0; i < leadingZeroes; i++) {
                builder.append("0");
            }
            builder.append(d);
            return builder.toString();
        }

        private String serializeWidth(int d) {
            int length = (int) Math.log10(d);
            if (d == 0) {
                return "000";
            }
            int leadingZeroes = windowWidthLength - length;
            StringBuilder builder = new StringBuilder(windowWidthLength);
            for (int i = 0; i < leadingZeroes; i++) {
                builder.append("0");
            }
            builder.append(d);
            return builder.toString();
        }

        /**
         * We assume that there is 1 bit of entropy in the x and 1 bit of entropy in the
         * y position
         */
        @Override
        public int getMinEntropyInBit() {
            return xPositions.size() * 2 + yPositions.size() * 2;
        }

        public int upperBoundForUniqueRepresentation() {
            return windowHeigthLength + windowWidthLength;
        }

    }
}
