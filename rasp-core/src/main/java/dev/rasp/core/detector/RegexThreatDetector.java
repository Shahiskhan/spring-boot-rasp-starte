package dev.rasp.core.detector;

import dev.rasp.core.DetectionResult;
import dev.rasp.core.PatternCache;
import dev.rasp.core.ScanContext;
import dev.rasp.core.ThreatDetector;
import dev.rasp.core.ThreatType;
import dev.rasp.core.extract.Payload;
import dev.rasp.core.extract.ScanPayloads;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Shared immutable matching machinery; rules use bounded spans instead of nested ambiguous quantifiers. */
abstract class RegexThreatDetector implements ThreatDetector {
    private final ThreatType type;
    private final int priority;
    private final int score;
    private final List<Pattern> rules;

    RegexThreatDetector(ThreatType type, int priority, int score, PatternCache cache, String... rules) {
        this.type = type;
        this.priority = priority;
        this.score = score;
        Objects.requireNonNull(cache, "cache");
        this.rules = java.util.Arrays.stream(rules).map(cache::compile).toList();
    }

    @Override public final ThreatType getType() { return type; }
    @Override public final int getPriority() { return priority; }

    @Override public boolean usesPreparedPayloads() { return true; }

    @Override public DetectionResult detect(ScanContext context) {
        Objects.requireNonNull(context, "context");
        return detectPrepared(context, ScanPayloads.normalizedFrom(context));
    }

    @Override public DetectionResult detectPrepared(ScanContext context, List<Payload> normalizedPayloads) {
        Objects.requireNonNull(context, "context");
        for (Payload payload : normalizedPayloads) {
            if (!mayMatch(payload.value())) continue;
            DetectionResult result = match(payload.value(), payload.location());
            if (result.detected()) return result;
        }
        return DetectionResult.clean(type);
    }

    /** Necessary input syntax only; this precheck must never replace a matching rule. */
    protected boolean mayMatch(String normalized) { return true; }

    protected static boolean containsAny(String value, String characters) {
        for (int i = 0; i < characters.length(); i++) if (value.indexOf(characters.charAt(i)) >= 0) return true;
        return false;
    }

    protected static boolean containsNonAscii(String value) {
        for (int i = 0; i < value.length(); i++) if (value.charAt(i) > 127) return true;
        return false;
    }

    protected DetectionResult match(String normalized, String location) {
        for (Pattern rule : rules) {
            Matcher matcher = rule.matcher(normalized);
            if (matcher.find()) {
                // Retain only the matched bounded rule evidence, never a full request body.
                String evidence = matcher.group();
                if (evidence.length() > 128) evidence = evidence.substring(0, 128);
                return new DetectionResult(type, true, score, evidence, location);
            }
        }
        return DetectionResult.clean(type);
    }
}
