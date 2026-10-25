package dev.rasp.autoconfigure;

import dev.rasp.core.Decision;
import dev.rasp.core.DetectionResult;
import org.springframework.context.ApplicationEvent;

/** Safe metadata event. Evidence is redacted before publication; request bodies and secrets are never included. */
public final class ThreatDetectedEvent extends ApplicationEvent {
    private final DetectionResult detection;
    private final Decision decision;
    private final String traceId;
    /** Constructs the threat detected event with its required collaborators. */
    public ThreatDetectedEvent(Object source, DetectionResult detection, Decision decision, String traceId) {
        super(source);
        this.detection = new DetectionResult(detection.type(), detection.detected(), detection.score(), "[REDACTED]", safeLocation(detection.location()));
        this.decision = decision;
        this.traceId = traceId;
    }
    private static String safeLocation(String location) {
        int separator = location.indexOf(':');
        return separator < 0 ? "request" : location.substring(0, separator);
    }
    /** Returns detection. */
    public DetectionResult getDetection() { return detection; }
    /** Returns decision. */
    public Decision getDecision() { return decision; }
    /** Returns trace id. */
    public String getTraceId() { return traceId; }
}
