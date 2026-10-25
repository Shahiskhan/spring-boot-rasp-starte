package dev.rasp.core.detector;

import static org.junit.jupiter.api.Assertions.*;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class SqlInjectionDetectorTest {
    private final SqlInjectionDetector detector = new SqlInjectionDetector();
    @ParameterizedTest @MethodSource("attacks") void recognizesSqlGrammar(String value) {
        var result = detector.detect(DetectorTestSupport.query(value));
        assertTrue(result.detected(), () -> "Expected SQLI detection: " + value);
        assertEquals(90, result.score());
        assertEquals("param:q", result.location());
    }
    @ParameterizedTest @MethodSource("benign") void acceptsCommonInputs(String value) {
        assertFalse(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    static Stream<String> attacks() { return Stream.of(
            "' OR 1=1--", "' oR 2=2 #", "x' and 9=9", "OR 'a'='a'", "and \"x\"=\"x\"",
            "UNION SELECT password FROM users", "1 union all select 1,2", "union distinct select secret", "uNiOn SeLeCt 1",
            "union\nselect 1", "union\tselect 1", "union%20select%201", "union%2520select%25201", "uni/**/on select 1", "union/**/select 1",
            "un/**/ion/**/select 1", "union/**/all/**/select 1", "union/**/distinct/**/select 1", "union/*hello*/all select 1", "sleep(5)", "pg_sleep (3)", "benchmark(1000,md5('a'))",
            "1;select 1", "1; drop table users", "x;INSERT INTO users VALUES(1)", "x; update users set x=1", "x;delete from users",
            "x; truncate users", "x;alter table users", "x;exec proc", "admin'--", "admin\"#", "admin'/*", "information_schema.tables",
            "INFORMATION_SCHEMA . columns", "extractvalue(1,concat(1))", "updatexml (1,2,3)", "load_file('/etc/passwd')",
            "select 0x61626364", "0x61646d696e313233", "%27%20or%201%3d1--", "&#39; or 1=1--", "union\u0000 select 1"
    ); }
    static Stream<String> benign() { return Stream.of(
            "John", "O'Connor", "Alice and Bob", "Rock & Roll", "union membership", "select a color", "please select this item",
            "and blue=green", "or name=value", "--help", "#hashtag", "hello/*world", "2026-10-25", "email+tag@example.test",
            "https://example.test/a?x=1&y=2", "information about schema", "load_file documentation", "SLEEPING WELL", "benchmark results",
            "some text; another sentence", "0xdeadbeef", "a ORANGE", "delete account", "DROP shipping", "{\"name\":\"John\"}",
            "a%b", "100%", "Robert');", "Books: SQL and databases", "quote: ' hello", "Math: 1=1", "unicode: café", "unionselect", "unionallselect"
    ); }
}
