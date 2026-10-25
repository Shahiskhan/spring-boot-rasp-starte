package dev.rasp.core;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class FalsePositiveTest {
    private final RaspEngine engine = new RaspEngine(RaspEngineTest.detectors(), RaspMode.BLOCK, true, 50);
    @ParameterizedTest @MethodSource("normalInputs") void realWorldInputCorpusIsAllowed(String input) {
        assertEquals(Decision.ALLOW, engine.scan(RaspEngineTest.query(input)).decision(), input);
    }
    static Stream<String> normalInputs() { return Stream.of(
            "O'Connor", "D'Angelo", "Alice & Bob", "Jane (admin)", "hello@example.test", "one+two@example.test", "https://example.test/a?x=1&y=2#section",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.ZXhhbXBsZQ", "^[a-zA-Z0-9_]+$", "^(?:foo|bar)$", "[0-9]{2,4}",
            "{\"name\":\"John\",\"active\":true}", "${spring.application.name}", "#{user.name}", "cost $10.00", "select your preferred color", "union of the sets",
            "2026-10-25T12:00:00+05:00", "a/b/c.txt", "report-final_v2.pdf", "Bearer eyJhbGciOiJIUzI1NiJ9", "password-with-!@#%&characters", "Unicode: café, 用户, مرحبا",
            Base64.getEncoder().encodeToString("Binary attachment test".getBytes(StandardCharsets.UTF_8)), "12.50 USD", "a && b", "onload documentation", "Math: 2+2=4"
    ); }
    @Test void ordinaryStructuredJsonAndLoginFieldsAreAllowed() {
        var input = new ScanContext("POST", "/api/login", Map.of("Content-Type", new String[]{"application/json"}, "Authorization", new String[]{"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln"}),
                Map.of(), "{\"name\":\"O'Connor\",\"password\":\"p@ssw0rd!\",\"tags\":[\"a\",\"b\"],\"settings\":{\"enabled\":true}}", Map.of(), null, "192.0.2.1", "trace");
        assertEquals(Decision.ALLOW, engine.scan(input).decision());
    }
    @Test void maliciousUnicodeEscapedJsonValuesAreStillBlocked() {
        var input = new ScanContext("POST", "/api/comment", Map.of("Content-Type", new String[]{"application/json"}), Map.of(),
                "{\"comment\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\"}", Map.of(), null, "ip", "trace");
        assertTrue(engine.scan(input).blocked());
    }
    @Test void malformedJsonDoesNotCauseFailOpenBypass() {
        var input = new ScanContext("POST", "/api/comment", Map.of("Content-Type", new String[]{"application/json"}), Map.of(),
                "{\"comment\":\"<script>alert(1)</script>\"", Map.of(), null, "ip", "trace");
        var result = engine.scan(input);
        assertTrue(result.blocked());
        assertFalse(result.engineError());
    }
}
