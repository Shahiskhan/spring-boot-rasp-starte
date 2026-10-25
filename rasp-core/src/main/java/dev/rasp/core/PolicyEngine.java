package dev.rasp.core;

import java.util.Objects;

/** Deterministic, immutable decision policy shared by HTTP and annotated service scans. */
public final class PolicyEngine {
    private final RaspMode mode;
    private final boolean failOpen;
    private final int threshold;

    /** Configure a confidence threshold of 1–100 and explicit failure behavior. */
    public PolicyEngine(RaspMode mode, boolean failOpen, int threshold) {
        this.mode = Objects.requireNonNull(mode, "mode");
        this.failOpen = failOpen;
        if (threshold < 1 || threshold > 100) throw new IllegalArgumentException("threshold must be between 1 and 100");
        this.threshold = threshold;
    }

    /** Errors may fail closed; a MONITOR deployment never blocks threat findings. */
    public Decision decide(int score, boolean engineError) {
        if (engineError && !failOpen) return Decision.BLOCK;
        if (score == 0) return engineError ? Decision.LOG : Decision.ALLOW;
        return mode == RaspMode.MONITOR || score < threshold ? Decision.LOG : Decision.BLOCK;
    }
}
