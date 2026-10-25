package dev.rasp.core.detector;

import dev.rasp.core.PatternCache;
import dev.rasp.core.ThreatType;

/** Detects MongoDB query operator injection in parameter names, JSON keys and textual input. */
public final class NoSqlInjectionDetector extends RegexThreatDetector {
    /** Construct with default caching. */
    public NoSqlInjectionDetector() { this(new PatternCache()); }
    /** Precompile rules using a shared cache. */
    public NoSqlInjectionDetector(PatternCache cache) {
        super(ThreatType.NOSQL, 70, 85, cache,
                "\\$(?:ne|gte?|lte?|where|regex|in|nin|or|and|not|expr|exists)\\b",
                "\\bthis\\.[a-z_][a-z0-9_]{0,63}\\s{0,8}(?:==|!=|>|<)");
    }
    @Override protected boolean mayMatch(String value) { return value.indexOf('$') >= 0 || value.contains("this.") || containsNonAscii(value); }
}
