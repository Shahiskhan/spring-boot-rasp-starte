package dev.rasp.core.detector;

import dev.rasp.core.PatternCache;
import dev.rasp.core.ThreatType;

/** Detects parent-directory segments and common sensitive absolute file paths. */
public final class PathTraversalDetector extends RegexThreatDetector {
    /** Construct with default caching. */
    public PathTraversalDetector() { this(new PatternCache()); }
    /** Precompile rules using a shared cache. */
    public PathTraversalDetector(PatternCache cache) {
        super(ThreatType.PATH_TRAVERSAL, 80, 90, cache,
                "(?:^|[/\\\\])\\.\\.(?:[/\\\\]|$)",
                "(?:^|[^a-z0-9])/(?:etc/(?:passwd|shadow)|proc/self/(?:environ|cmdline))\\b",
                "\\b[a-z]:[/\\\\]windows(?:[/\\\\]|$)");
    }
    @Override protected boolean mayMatch(String value) { return containsAny(value, "/\\") || value.equals(".."); }
}
