package dev.rasp.core.detector;

import dev.rasp.core.DetectionResult;
import dev.rasp.core.PatternCache;
import dev.rasp.core.ThreatType;
import java.util.regex.Pattern;

/** Detects SQL grammar combinations rather than punctuation or ordinary SQL-related words alone. */
public final class SqlInjectionDetector extends RegexThreatDetector {
    private final Pattern commentJoinedUnion;
    /** Construct with the default bounded pattern cache. */
    public SqlInjectionDetector() { this(new PatternCache()); }
    /** Construct and precompile patterns using a shared bounded cache. */
    public SqlInjectionDetector(PatternCache cache) {
        super(ThreatType.SQLI, 100, 90, cache,
                "\\bunion\\b.{0,256}?\\bselect\\b",
                "\\b(?:or|and)\\s{1,32}(?:[0-9]{1,16}\\s{0,32}=\\s{0,32}[0-9]{1,16}|['\"][^'\"\\r\\n]{0,64}['\"]\\s{0,32}=\\s{0,32}['\"][^'\"\\r\\n]{0,64}['\"])",
                "\\b(?:sleep|benchmark|pg_sleep)\\s{0,32}\\(",
                ";\\s{0,32}(?:select|insert|update|delete|drop|alter|truncate|exec)\\b",
                "['\"]\\s{0,32}(?:--|#|/\\*)",
                "\\binformation_schema\\s{0,8}\\.\\s{0,8}(?:tables|columns)\\b",
                "\\b(?:extractvalue|updatexml|load_file)\\s{0,32}\\(",
                "\\b(?:select|union|or|and)\\b.{0,64}?\\b0x[0-9a-f]{4,}\\b",
                "\\b0x[0-9a-f]{12,}\\b");
        commentJoinedUnion = cache.compile("\\bunion(?:all|distinct)?select\\b");
    }

    @Override protected boolean mayMatch(String value) {
        // Every rule needs SQL whitespace/punctuation or a hexadecimal literal; comments require '/'.
        return containsAny(value, " \t\n\r\f\u000b'\";(./") || value.contains("0x");
    }

    @Override protected DetectionResult match(String normalized, String location) {
        DetectionResult direct = super.match(normalized, location);
        if (direct.detected() || !normalized.contains("/*")) return direct;
        // Both variants cover keyword splitting (un/**/ion) and token separating (union/**/select).
        String joinedText = stripComments(normalized, false);
        DetectionResult joined = super.match(joinedText, location);
        var matcher = commentJoinedUnion.matcher(joinedText);
        // Only consider concatenated grammar after comments were actually present in the original input.
        if (!joined.detected() && matcher.find()) return new DetectionResult(ThreatType.SQLI, true, 90, matcher.group(), location);
        return joined.detected() ? joined : super.match(stripComments(normalized, true), location);
    }

    private static String stripComments(String text, boolean space) {
        StringBuilder result = new StringBuilder(text.length());
        for (int i = 0; i < text.length();) {
            if (i + 1 < text.length() && text.charAt(i) == '/' && text.charAt(i + 1) == '*') {
                int end = text.indexOf("*/", i + 2);
                if (end < 0) { result.append(text, i, text.length()); break; }
                if (space) result.append(' ');
                i = end + 2;
            } else result.append(text.charAt(i++));
        }
        return result.toString();
    }
}
