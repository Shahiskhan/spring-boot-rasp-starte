package dev.rasp.autoconfigure;

import dev.rasp.core.ThreatType;
import jakarta.servlet.http.HttpServletRequest;

import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

/** Request-scoped bookkeeping; no caller-supplied identifier or payload is copied into logs. */
final class RaspRequestState {
    static final String ATTRIBUTE = RaspRequestState.class.getName();
    final String traceId = UUID.randomUUID().toString();
    final Set<ThreatType> detected = EnumSet.noneOf(ThreatType.class);
    final Set<ThreatType> blocked = EnumSet.noneOf(ThreatType.class);
    boolean exempt;
    boolean violationRecorded;
    boolean oversized;

    static RaspRequestState of(HttpServletRequest request) {
        Object existing = request.getAttribute(ATTRIBUTE);
        if (existing instanceof RaspRequestState state) return state;
        var state = new RaspRequestState();
        request.setAttribute(ATTRIBUTE, state);
        return state;
    }
}
