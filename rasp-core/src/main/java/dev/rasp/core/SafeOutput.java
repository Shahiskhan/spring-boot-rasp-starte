package dev.rasp.core;

import org.owasp.encoder.Encode;

/** Explicit contextual output encoding. RASP does not alter request input or arbitrary JSON responses. */
public final class SafeOutput {
    private SafeOutput() { }
    /** Encode an untrusted string for HTML text content; use a different encoder for other contexts. */
    public static String forHtml(String input) { return Encode.forHtml(input == null ? "" : input); }
}
