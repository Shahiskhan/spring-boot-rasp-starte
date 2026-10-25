package dev.rasp.core.detector;

import dev.rasp.core.PatternCache;
import dev.rasp.core.ThreatType;

/** Detects execution-oriented expression syntax while allowing ordinary JSON braces and placeholders. */
public final class SpelInjectionDetector extends RegexThreatDetector {
    /** Construct with default caching. */
    public SpelInjectionDetector() { this(new PatternCache()); }
    /** Precompile rules using a shared cache. */
    public SpelInjectionDetector(PatternCache cache) {
        super(ThreatType.SPEL, 95, 95, cache,
                "\\bt\\s{0,16}\\(\\s{0,16}(?:java\\.lang\\.(?:runtime|processbuilder|system)|java\\.nio\\.file\\.files)\\b",
                "\\b(?:getclass|forname|getruntime)\\s{0,32}\\(",
                "\\.\\s{0,8}(?:exec|invoke|newinstance)\\s{0,32}\\(",
                "\\b(?:classloader|scriptenginemanager)\\b",
                "[#\\$]\\{[^}\\r\\n]{0,128}(?:[+*/=()'\"]|\\bnew\\b)[^}\\r\\n]{0,128}\\}",
                "\\beval\\s{0,32}\\(");
    }
    @Override protected boolean mayMatch(String value) {
        return containsAny(value, "({") || value.contains("classloader") || value.contains("scriptenginemanager") || containsNonAscii(value);
    }
}
