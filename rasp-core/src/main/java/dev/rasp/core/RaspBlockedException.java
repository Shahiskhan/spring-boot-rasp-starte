package dev.rasp.core;

import java.util.Objects;

/** Raised at integration boundaries when RASP denies an operation. Never carries raw input in its message. */
public final class RaspBlockedException extends RuntimeException {
    private final ScanResult result;
    private final String traceId;
    /** Create an exception with a constant, payload-free message. */
    public RaspBlockedException(ScanResult result, String traceId) {
        super("Operation blocked by runtime application protection");
        this.result = Objects.requireNonNull(result, "result");
        this.traceId = traceId == null ? "" : traceId;
    }
    /** Associated policy decision. */
    public ScanResult result() { return result; }
    /** Server-generated correlation identifier. */
    public String traceId() { return traceId; }
    /** Associated policy decision, bean accessor. */
    public ScanResult getResult() { return result; }
    /** Server-generated correlation identifier, bean accessor. */
    public String getTraceId() { return traceId; }
}
