package dev.rasp.core;

import dev.rasp.core.extract.Payload;
import java.util.List;

/** Thread-safe strategy that inspects immutable request input without performing network I/O. */
public interface ThreatDetector {
    /** Return this strategy's highest-confidence finding, or a clean result. */
    DetectionResult detect(ScanContext context);
    /** Threat family handled by this strategy. */
    ThreatType getType();
    /** Higher values execute earlier. */
    int getPriority();
    /** Opt in to request-local extraction/canonicalization shared across built-in strategies. Custom strategies default to the original API. */
    default boolean usesPreparedPayloads() { return false; }
    /** Inspect values that have already undergone exactly two normalization passes. The default preserves custom strategy behavior. */
    default DetectionResult detectPrepared(ScanContext context, List<Payload> normalizedPayloads) { return detect(context); }
}
