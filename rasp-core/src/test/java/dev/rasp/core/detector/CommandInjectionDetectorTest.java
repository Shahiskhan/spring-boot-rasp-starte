package dev.rasp.core.detector;

import static org.junit.jupiter.api.Assertions.*;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class CommandInjectionDetectorTest {
    private final CommandInjectionDetector detector = new CommandInjectionDetector();
    @ParameterizedTest @MethodSource("attacks") void recognizesShellExecutionSyntax(String value) {
        assertTrue(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    @ParameterizedTest @MethodSource("benign") void acceptsCommonPunctuationAndWords(String value) {
        assertFalse(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    static Stream<String> attacks() { return Stream.of(
            "hello; whoami", "hello|id", "hello && uname -a", "x || curl https://example.test", "x;cat /tmp/a", "x;ls -la", "x;wget example.test",
            "x;nc 192.0.2.1 123", "x;bash -c x", "x;sh -c x", "x;echo test", "x;pwd", "x;sleep 10", "x;ping example.test", "x;rm /tmp/a",
            "$(id)", "$(echo hello)", "`whoami`", "`uname -a`", "/bin/sh -c echo", "cmd.exe /c echo", "powershell -command echo",
            "> /etc/passwd", "< /dev/null", "x;%77hoami", "x%3b%20id", "x%253b%2520id", "x; /usr/bin/id", "$(cat /tmp/a)", "powerſhell -command echo", "/bın/sh -c echo"
    ); }
    static Stream<String> benign() { return Stream.of(
            "John", "Rock & Roll", "a && b", "a | b", "one; two", "$10", "cost $5.00", "${name}", "hello`world", "a+b=c", "id 12345", "uname documentation",
            "bash scripting guide", "cat picture", "curl your hair", "https://example.test/?a=1&b=2", "a < b", "x > 3", "regex: [;&|]", "plain JSON {x:1}",
            "hello\\nworld", "mail+tag@example.test", "C:\\Users\\Alice", "<p>hello</p>", "ls", "whoami", "price: $100", "unicode: café"
    ); }
}
