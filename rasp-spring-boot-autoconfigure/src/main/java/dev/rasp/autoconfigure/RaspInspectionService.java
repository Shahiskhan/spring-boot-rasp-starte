package dev.rasp.autoconfigure;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.rasp.core.Decision;
import dev.rasp.core.DetectionResult;
import dev.rasp.core.RaspBlockedException;
import dev.rasp.core.RaspEngine;
import dev.rasp.core.RaspMode;
import dev.rasp.core.ScanContext;
import dev.rasp.core.ScanResult;
import dev.rasp.core.ThreatType;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.util.AntPathMatcher;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/** Shared policy, safe observability and bounded STRICT-mode IP state for all interception paths. */
public final class RaspInspectionService {
    private static final Logger LOG = LoggerFactory.getLogger(RaspInspectionService.class);
    private final RaspEngine engine;
    private final RaspProperties properties;
    private final ApplicationEventPublisher events;
    private final ObjectProvider<RaspMetricsBinder> metrics;
    private final Cache<String, Violations> violations;
    private final AntPathMatcher paths = new AntPathMatcher();

    /** Constructs the rasp inspection service with its required collaborators. */
    public RaspInspectionService(RaspEngine engine, RaspProperties properties, ApplicationEventPublisher events,
                                 ObjectProvider<RaspMetricsBinder> metrics) {
        this.engine = engine; this.properties = properties; this.events = events; this.metrics = metrics;
        violations = Caffeine.newBuilder().maximumSize(properties.getRateLimit().getMaxEntries())
                .expireAfterWrite(Duration.ofSeconds(Math.max(properties.getRateLimit().getWindowSeconds(), properties.getRateLimit().getBlockSeconds())))
                .build();
    }
    boolean exempt(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (properties.getWhitelist().getIps().contains(request.getRemoteAddr())) return true;
        // A whitelist is a security bypass: ambiguous or non-canonical paths must be scanned instead.
        if (path.contains("%") || path.contains("\\") || path.contains(";") || path.contains("//")
                || java.util.Arrays.stream(path.split("/")).anyMatch(part -> part.equals(".") || part.equals(".."))) return false;
        return properties.getWhitelist().getPaths().stream().anyMatch(pattern -> paths.match(pattern, path));
    }
    void beforeRequest(HttpServletRequest request) {
        if (properties.getMode() != RaspMode.STRICT) return;
        Violations recent = violations.getIfPresent(request.getRemoteAddr());
        if (recent != null && recent.blockedUntil > System.currentTimeMillis()) {
            throw new RaspBlockedException(new ScanResult(List.of(), 100, Decision.BLOCK, false), RaspRequestState.of(request).traceId);
        }
    }
    /** Provides the inspect operation for the RASP integration. */
    public ScanResult inspect(ScanContext context, HttpServletRequest request, Set<ThreatType> types) {
        if (request != null && RaspRequestState.of(request).exempt) return new ScanResult(List.of(), 0, Decision.ALLOW, false);
        ScanResult result = engine.scan(context, types);
        if (result.engineError()) LOG.warn("RASP detector error trace_id={} decision={}", context.traceId(), result.decision());
        RaspRequestState state = request == null ? new RaspRequestState() : RaspRequestState.of(request);
        synchronized (state) {
            for (DetectionResult detection : result.detections()) {
                if (state.detected.add(detection.type())) {
                    metric(detection.type(), false);
                    LOG.warn("RASP threat trace_id={} type={} decision={} score={}", context.traceId(), detection.type(), result.decision(), detection.score());
                    try { events.publishEvent(new ThreatDetectedEvent(this, detection, result.decision(), context.traceId())); }
                    catch (RuntimeException listenerFailure) { LOG.warn("RASP event listener failed trace_id={}", context.traceId()); }
                }
                if (result.blocked() && state.blocked.add(detection.type())) {
                    metric(detection.type(), true);
                }
            }
            if (result.blocked() && !state.violationRecorded && properties.getMode() == RaspMode.STRICT && request != null) {
                state.violationRecorded = true;
                recordViolation(request.getRemoteAddr());
            }
        }
        if (result.blocked()) throw new RaspBlockedException(result, context.traceId());
        return result;
    }
    void extractionFailure(HttpServletRequest request) {
        extractionFailure(RaspRequestState.of(request).traceId);
    }
    private void metric(ThreatType type, boolean blocked) {
        try {
            RaspMetricsBinder binder = metrics.getIfAvailable();
            if (binder != null) {
                if (blocked) binder.blocked(type); else binder.detected(type);
            }
        } catch (RuntimeException metricFailure) { LOG.warn("RASP metric recording failed type={}", type); }
    }
    void extractionFailure(String trace) {
        LOG.warn("RASP extraction failed trace_id={} fail_open={}", trace, properties.isFailOpen());
        if (!properties.isFailOpen() && properties.getMode() != RaspMode.MONITOR) throw new RaspBlockedException(new ScanResult(List.of(), 100, Decision.BLOCK, true), trace);
    }
    private void recordViolation(String ip) {
        long now = System.currentTimeMillis();
        var limits = properties.getRateLimit();
        violations.asMap().compute(ip, (ignored, previous) -> {
            boolean newWindow = previous == null || now - previous.started >= limits.getWindowSeconds() * 1000;
            long started = newWindow ? now : previous.started;
            int count = newWindow ? 1 : previous.count + 1;
            long until = count >= limits.getViolationThreshold() ? now + limits.getBlockSeconds() * 1000 : 0;
            return new Violations(started, count, until);
        });
    }
    private record Violations(long started, int count, long blockedUntil) { }
}
