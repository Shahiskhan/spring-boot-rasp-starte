package dev.rasp.core.detector;

import static org.junit.jupiter.api.Assertions.*;
import dev.rasp.core.ScanContext;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class NoSqlInjectionDetectorTest {
    private final NoSqlInjectionDetector detector = new NoSqlInjectionDetector();
    @ParameterizedTest @MethodSource("attacks") void recognizesQueryOperators(String value) {
        assertTrue(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    @ParameterizedTest @MethodSource("benign") void acceptsCurrencyAndRegularJson(String value) {
        assertFalse(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    @Test void scansOperatorKeys() {
        var context = new ScanContext("POST", "/api/users", Map.of(), Map.of("q[$ne]", new String[]{"alice"}), null, Map.of(), null, "192.0.2.1", "trace");
        assertTrue(detector.detect(context).detected());
        context = new ScanContext("POST", "/api/users", Map.of(), Map.of(), null, Map.of("user", Map.of("$ne", "alice")), null, "192.0.2.1", "trace");
        assertTrue(detector.detect(context).detected());
    }
    static Stream<String> attacks() { return Stream.of(
            "$ne", "$gt", "$gte", "$lt", "$lte", "$where", "$regex", "$in", "$nin", "$or", "$and", "$not", "$expr", "$exists", "{\"$where\":\"1==1\"}",
            "this.password != null", "this.age > 1", "this.x==1", "%24ne", "%2524where", "q[$regex]", "{\"a\":{\"$gt\":0}}", "thıſ.age>1"
    ); }
    static Stream<String> benign() { return Stream.of(
            "John", "$10", "$100.00", "cost $5", "${name}", "${spring.profiles.active}", "$network", "$origin", "$index", "$letter", "$android",
            "{\"name\":\"John\"}", "{\"age\":20}", "normal regex [a-z]+", "mongodb guide", "this is fine", "this.title", "name=value", "a>b", "a==b",
            "mail@example.test", "price=10", "a+b", "quote ' hello"
    ); }
}
