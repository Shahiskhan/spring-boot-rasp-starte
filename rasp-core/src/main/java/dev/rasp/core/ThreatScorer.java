package dev.rasp.core;

import java.util.Collection;

/** Uses maximum confidence so repeated low-confidence rules cannot amplify each other into a block. */
public final class ThreatScorer {
    /** Score the highest-confidence detected finding on a 0–100 scale. */
    public int score(Collection<DetectionResult> findings) {
        return findings.stream().filter(DetectionResult::detected).mapToInt(DetectionResult::score).max().orElse(0);
    }
}
