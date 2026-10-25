package dev.rasp.core.extract;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

/** Parses JSON including escaped Unicode and nested arrays. No polymorphic typing is enabled. */
public final class JsonBodyExtractor implements PayloadExtractor {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    @Override public List<Payload> extract(String body) {
        if (body == null || body.isBlank()) return List.of();
        try {
            List<Payload> result = new ArrayList<>();
            ScanPayloads.flatten("body:$", MAPPER.readValue(body, Object.class), result);
            return List.copyOf(result);
        } catch (JsonProcessingException ex) { throw new IllegalArgumentException("Malformed JSON body"); }
    }
}
