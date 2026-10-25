package dev.rasp.core.extract;

/** A single named textual input surface. Its value must never be sent to logs or alert payloads. */
public record Payload(String location, String value) {
    /** Hide the payload from accidental diagnostic logging. */
    @Override public String toString() { return "Payload[value redacted]"; }
}
