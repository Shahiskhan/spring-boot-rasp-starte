package dev.rasp.core.extract;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Decodes URL-encoded form keys and values, preserving duplicate fields as separate payloads. */
public final class FormBodyExtractor implements PayloadExtractor {
    @Override public List<Payload> extract(String body) {
        if (body == null || body.isEmpty()) return List.of();
        List<Payload> result = new ArrayList<>();
        for (String pair : body.split("&", -1)) {
            String[] parts = pair.split("=", 2);
            try {
                String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                result.add(new Payload("form-name", key));
                result.add(new Payload("form:" + key, parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : ""));
            } catch (IllegalArgumentException ex) { throw new IllegalArgumentException("Malformed form encoding"); }
        }
        return List.copyOf(result);
    }
}
