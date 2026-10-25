package dev.rasp.autoconfigure;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

/** Reports that the configured RASP engine was constructed successfully. */
public final class RaspHealthIndicator implements HealthIndicator {
    private final RaspProperties properties;
    private final int detectorCount;
    /** Constructs the rasp health indicator with its required collaborators. */
    public RaspHealthIndicator(RaspProperties properties, int detectorCount) { this.properties = properties; this.detectorCount = detectorCount; }
    /** Provides the health operation for the RASP integration. */
    @Override public Health health() {
        return Health.up().withDetail("mode", properties.getMode().name()).withDetail("detectors", detectorCount)
                .withDetail("failOpen", properties.isFailOpen()).build();
    }
}
