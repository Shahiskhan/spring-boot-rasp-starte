package dev.rasp.core.detector;

import dev.rasp.core.ScanContext;
import java.util.Map;

final class DetectorTestSupport {
    static ScanContext query(String value) {
        return new ScanContext("GET", "/api/search", Map.of(), Map.of("q", new String[]{value}), null, Map.of(), null, "192.0.2.1", "test-trace");
    }
    static ScanContext xml(String value) {
        return new ScanContext("POST", "/api/xml", Map.of("Content-Type", new String[]{"application/xml; charset=UTF-8"}), Map.of(), value, Map.of(), null, "192.0.2.1", "test-trace");
    }
}
