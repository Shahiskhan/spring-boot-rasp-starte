package dev.rasp.core;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.util.Objects;
import java.util.regex.Pattern;

/** Bounded thread-safe cache of compiled patterns, populated while strategies are constructed. */
public final class PatternCache {
    private final Cache<String, Pattern> patterns;
    /** Defaults to 500 patterns retained for one hour. */
    public PatternCache() { this(500, Duration.ofHours(1)); }
    /** Configure positive capacity and expiry. */
    public PatternCache(long maximumSize, Duration ttl) {
        if (maximumSize < 1) throw new IllegalArgumentException("maximumSize must be positive");
        Objects.requireNonNull(ttl, "ttl");
        if (ttl.isZero() || ttl.isNegative()) throw new IllegalArgumentException("ttl must be positive");
        patterns = Caffeine.newBuilder().maximumSize(maximumSize).expireAfterAccess(ttl).build();
    }
    /** Compile with case-insensitive Unicode and dot-all matching, or reuse an existing immutable pattern. */
    public Pattern compile(String expression) {
        return patterns.get(Objects.requireNonNull(expression, "expression"),
                regex -> Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.UNICODE_CASE));
    }
}
