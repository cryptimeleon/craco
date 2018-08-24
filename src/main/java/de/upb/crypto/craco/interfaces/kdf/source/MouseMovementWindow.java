package de.upb.crypto.craco.interfaces.kdf.source;

import de.upb.crypto.craco.interfaces.kdf.source.MouseSourceOfRandomness.MousePositionKeyMaterial;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.util.concurrent.Semaphore;

public class MouseMovementWindow extends JFrame {

    private static final long serialVersionUID = -2852755773362684163L;

    private MousePositionKeyMaterial material;

    public MouseMovementWindow(int width, int height, MouseSourceOfRandomness source, Semaphore condition) {
        super();
        this.setSize(width, height);
        material = source.new MousePositionKeyMaterial();

        JPanel pane = new JPanel(new BorderLayout(5, 5));
        pane.setSize(this.getSize());

        JPanel rootPanel = new JPanel(new BorderLayout());
        this.setContentPane(rootPanel);
        rootPanel.add(pane, BorderLayout.CENTER);

        JProgressBar progress = new JProgressBar(0, source.getMinEntropy());
        rootPanel.add(progress, BorderLayout.NORTH);

        pane.addMouseMotionListener(new MouseMotionAdapter() {
            private int measurementOffset = 10;
            private long currentMeasurement = 0;

            @Override
            public void mouseMoved(MouseEvent e) {
                if (currentMeasurement % measurementOffset == 0) {
                    if (material.getMinEntropyInBit() < source.getMinEntropy()) {
                        material.updatePositions(e.getX(), e.getY());
                        progress.setValue(material.getMinEntropyInBit());
                    } else {
                        MouseMovementWindow.this.dispose();
                        condition.release();
                    }
                }
                currentMeasurement++;
            }
        });
        try {
            condition.acquire();
        } catch (InterruptedException e1) {
            Thread.currentThread().interrupt();
        }
        this.setVisible(true);
    }

    public MousePositionKeyMaterial getMaterial() {
        return material;
    }

}
