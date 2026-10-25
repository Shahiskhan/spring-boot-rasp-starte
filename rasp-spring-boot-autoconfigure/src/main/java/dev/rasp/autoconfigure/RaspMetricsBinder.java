package dev.rasp.autoconfigure;

import dev.rasp.core.ThreatType;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

import java.util.EnumMap;
import java.util.Map;

/** Registers only bounded threat-type tags; request values are never metric tags. */
public final class RaspMetricsBinder {
    private final Map<ThreatType, Counter> detected = new EnumMap<>(ThreatType.class);
    private final Map<ThreatType, Counter> blocked = new EnumMap<>(ThreatType.class);
    /** Constructs the rasp metrics binder with its required collaborators. */
    public RaspMetricsBinder(MeterRegistry registry) {
        for (ThreatType type : ThreatType.values()) {
            detected.put(type, Counter.builder("rasp.threats.detected").tag("type", type.name()).description("RASP threats detected").register(registry));
            blocked.put(type, Counter.builder("rasp.threats.blocked").tag("type", type.name()).description("RASP threats blocked").register(registry));
        }
    }
    /** Provides the detected operation for the RASP integration. */
    public void detected(ThreatType type) { detected.get(type).increment(); }
    /** Provides the blocked operation for the RASP integration. */
    public void blocked(ThreatType type) { blocked.get(type).increment(); }
}
