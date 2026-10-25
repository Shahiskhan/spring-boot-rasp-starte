package dev.rasp.core.detector;

import static org.junit.jupiter.api.Assertions.*;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class LdapInjectionDetectorTest {
    private final LdapInjectionDetector detector = new LdapInjectionDetector();
    @ParameterizedTest @MethodSource("attacks") void recognizesFilterBypasses(String value) {
        assertTrue(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    @ParameterizedTest @MethodSource("benign") void acceptsNamesAndOrdinaryPunctuation(String value) {
        assertFalse(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    static Stream<String> attacks() { return Stream.of(
            "*))", "*)(", "admin*)(uid=*)", "x)(|(uid=*))", "x)(&(uid=*))", "x)(!(uid=alice))", "(|(uid=*)(uid=admin))", "(&(uid=*)(cn=admin))",
            "(!(uid=*))", "x)(cn=*)", "* ) )", "%2a%29%29", "%252a%2529%2529", "alice*)(|(objectClass=*))", "))(|", "x) ( |(uid=alice))"
    ); }
    static Stream<String> benign() { return Stream.of(
            "John", "O'Connor", "Alice (admin)", "a*b", "*", "(uid=alice)", "uid=alice,ou=people,dc=example,dc=test", "a != b", "a | b", "hello!",
            "[a-z]*", "name=value", "(hello)", "(a)(b)", "{name}", "mail@example.test", "AND", "percent%20text", "unicode: 用户", "!important"
    ); }
}
