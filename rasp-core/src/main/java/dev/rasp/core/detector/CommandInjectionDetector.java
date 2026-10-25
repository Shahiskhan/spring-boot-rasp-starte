package dev.rasp.core.detector;

import dev.rasp.core.PatternCache;
import dev.rasp.core.ThreatType;

/** Detects shell chaining/substitution paired with command syntax, avoiding punctuation-only false positives. */
public final class CommandInjectionDetector extends RegexThreatDetector {
    /** Construct with default caching. */
    public CommandInjectionDetector() { this(new PatternCache()); }
    /** Precompile rules using a shared cache. */
    public CommandInjectionDetector(PatternCache cache) {
        super(ThreatType.COMMAND, 85, 90, cache,
                "(?:[;|]|&&)\\s{0,32}(?:/bin/|/usr/bin/)?(?:cat|ls|whoami|id|uname|curl|wget|nc|bash|sh|echo|pwd|rm|sleep|ping|powershell|cmd)(?:\\b|$)",
                "\\$\\(\\s{0,32}[^)\\r\\n]{1,256}\\)",
                "`\\s{0,16}(?:cat|ls|whoami|id|uname|curl|wget|nc|bash|sh|echo|pwd)\\b[^`\\r\\n]{0,128}`",
                "(?:^|[;|&]\\s{0,16})(?:/bin/(?:bash|sh)|cmd\\.exe|powershell(?:\\.exe)?)\\s{1,16}(?:-c|/c|-command)\\b",
                "[<>]\\s{0,16}/(?:etc|dev|tmp|proc)/");
    }
    @Override protected boolean mayMatch(String value) {
        return containsAny(value, ";|&$`<>") || value.startsWith("/bin/") || value.startsWith("cmd.exe") || value.startsWith("powershell") || containsNonAscii(value);
    }
}
