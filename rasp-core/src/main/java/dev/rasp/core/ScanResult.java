package dev.rasp.core;

import java.util.List;
import java.util.Objects;

/** Immutable request decision, including any detector failure without disclosing its message. */
public record ScanResult(List<DetectionResult> detections, int score, Decision decision, boolean engineError) {
    public ScanResult {
        detections = List.copyOf(detections);
        Objects.requireNonNull(decision, "decision");
        if (score < 0 || score > 100) throw new IllegalArgumentException("score must be between 0 and 100");
    }
    /** Whether the caller must reject this operation. */
    public boolean blocked() { return decision == Decision.BLOCK; }
    /** A clean scan result. */
    public static ScanResult allowed() { return new ScanResult(List.of(), 0, Decision.ALLOW, false); }
}
