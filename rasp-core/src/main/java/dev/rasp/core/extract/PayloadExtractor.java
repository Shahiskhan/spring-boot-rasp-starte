package dev.rasp.core.extract;

import java.util.List;

/** Extracts request-body text without evaluating expressions or resolving external resources. */
public interface PayloadExtractor {
    /** Return named values; malformed structures throw a payload-free IllegalArgumentException. */
    List<Payload> extract(String body);
}
