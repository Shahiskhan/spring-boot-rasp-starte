package dev.rasp.core;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import dev.rasp.core.extract.Payload;
import dev.rasp.core.extract.ScanPayloads;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Reusable synchronous CPU-only detection engine. Integrations own extraction, telemetry and blocking. */
public final class RaspEngine {
    private static final Logger LOG = LoggerFactory.getLogger(RaspEngine.class);
    private final List<ThreatDetector> detectors;
    private final PolicyEngine policy;
    private final ThreatScorer scorer = new ThreatScorer();

    /** Copy and order injected strategies; they must be thread safe. */
    public RaspEngine(List<ThreatDetector> detectors, RaspMode mode, boolean failOpen, int blockThreshold) {
        this.detectors = detectors.stream().map(d -> Objects.requireNonNull(d, "detector"))
                .sorted(Comparator.comparingInt(ThreatDetector::getPriority).reversed()).toList();
        this.policy = new PolicyEngine(mode, failOpen, blockThreshold);
    }

    /** Scan all installed threat strategies. */
    public ScanResult scan(ScanContext context) { return scan(context, Set.of()); }

    /** Run a scan using a caller-owned bounded executor; HTTP integration uses the synchronous CPU-only path. */
    public CompletableFuture<ScanResult> scanAsync(ScanContext context, Executor executor) {
        Objects.requireNonNull(executor, "executor");
        return CompletableFuture.supplyAsync(() -> scan(context), executor);
    }

    /** Scan selected families; an empty set means all. Detector errors never disclose input or exception text. */
    public ScanResult scan(ScanContext context, Set<ThreatType> selected) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(selected, "selected");
        List<DetectionResult> findings = new ArrayList<>();
        boolean error = false;
        List<Payload> prepared = null;
        RuntimeException preparationFailure = null;
        for (ThreatDetector detector : detectors) {
            if (!selected.isEmpty() && !selected.contains(detector.getType())) continue;
            try {
                DetectionResult result;
                if (detector.usesPreparedPayloads()) {
                    if (prepared == null && preparationFailure == null) {
                        try { prepared = ScanPayloads.normalizedFrom(context); }
                        catch (RuntimeException ex) { preparationFailure = ex; }
                    }
                    if (preparationFailure != null) throw preparationFailure;
                    result = detector.detectPrepared(context, prepared);
                } else result = detector.detect(context);
                Objects.requireNonNull(result, "detector result");
                if (result.detected()) findings.add(result);
            } catch (RuntimeException ex) {
                error = true;
                LOG.warn("RASP detector failed type={} exceptionType={}", detector.getType(), ex.getClass().getSimpleName());
            }
        }
        int score = scorer.score(findings);
        return new ScanResult(findings, score, policy.decide(score, error), error);
    }
}
