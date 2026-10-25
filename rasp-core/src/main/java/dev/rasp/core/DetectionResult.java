package dev.rasp.core;

import java.util.Objects;

/** One detector's result. Evidence must never be logged or returned to HTTP clients. */
public record DetectionResult(ThreatType type, boolean detected, int score, String evidence, String location) {
    public DetectionResult {
        Objects.requireNonNull(type, "type");
        if (score < 0 || score > 100) throw new IllegalArgumentException("score must be between 0 and 100");
        evidence = evidence == null ? "" : evidence;
        location = location == null ? "" : location;
    }

    /** An empty detector result. */
    public static DetectionResult clean(ThreatType type) { return new DetectionResult(type, false, 0, "", ""); }

    /** Keep toString safe even if a containing object is accidentally logged. */
    @Override public String toString() {
        return "DetectionResult[type=" + type + ", detected=" + detected + ", score=" + score + "]";
    }
}
