package dev.rasp.core.detector;

import dev.rasp.core.PatternCache;
import dev.rasp.core.ThreatType;

/** Detects LDAP filter termination, wildcard bypass and injected boolean filter operators. */
public final class LdapInjectionDetector extends RegexThreatDetector {
    /** Construct with default caching. */
    public LdapInjectionDetector() { this(new PatternCache()); }
    /** Precompile rules using a shared cache. */
    public LdapInjectionDetector(PatternCache cache) {
        super(ThreatType.LDAP, 70, 80, cache,
                "\\*\\s{0,8}\\)\\s{0,8}(?:\\)|\\()",
                "\\)\\s{0,8}\\(\\s{0,8}[|&!]",
                "\\(\\s{0,8}[|&!]\\s{0,8}\\([^)]{0,64}=\\s{0,8}\\*",
                "\\)\\s{0,8}\\([^)]{1,64}=\\s{0,8}\\*\\)");
    }
    @Override protected boolean mayMatch(String value) { return containsAny(value, "()"); }
}
