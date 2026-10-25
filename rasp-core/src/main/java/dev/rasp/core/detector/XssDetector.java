package dev.rasp.core.detector;

import dev.rasp.core.PatternCache;
import dev.rasp.core.ThreatType;

/** Detects active markup and scripting primitives after bounded canonicalization. */
public final class XssDetector extends RegexThreatDetector {
    /** Construct with default caching. */
    public XssDetector() { this(new PatternCache()); }
    /** Precompile rules using a shared cache. */
    public XssDetector(PatternCache cache) {
        super(ThreatType.XSS, 90, 90, cache,
                "<\\s{0,32}/?\\s{0,32}(?:script|iframe|object|embed)\\b",
                "\\bon(?:error|load|click|mouseover|focus|animationstart|pointerenter|mouseenter|toggle|submit)\\s{0,32}=",
                "(?:java\\s{0,8}script|vbscript)\\s{0,16}:",
                "data\\s{0,8}:\\s{0,8}(?:text/html|application/xhtml\\+xml)",
                "\\bdocument\\s{0,8}\\.\\s{0,8}(?:cookie|write|location)\\b",
                "\\beval\\s{0,32}\\(");
    }
    @Override protected boolean mayMatch(String value) { return containsAny(value, "<=:.("); }
}
