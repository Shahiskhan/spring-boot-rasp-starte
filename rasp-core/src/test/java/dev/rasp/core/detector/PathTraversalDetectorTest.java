package dev.rasp.core.detector;

import static org.junit.jupiter.api.Assertions.*;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class PathTraversalDetectorTest {
    private final PathTraversalDetector detector = new PathTraversalDetector();
    @ParameterizedTest @MethodSource("attacks") void recognizesTraversalAndSensitiveFiles(String value) {
        assertTrue(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    @ParameterizedTest @MethodSource("benign") void acceptsOrdinaryPaths(String value) {
        assertFalse(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    static Stream<String> attacks() { return Stream.of("../secret", "../../secret", "a/../secret", "..\\secret", "a\\..\\secret", "%2e%2e%2fsecret", "%252e%252e%252fsecret",
            "..%5csecret", "%2E%2E%5Csecret", "..%2fsecret", "/etc/passwd", "/etc/shadow", "C:\\Windows\\win.ini", "c:/windows/system.ini", "/proc/self/environ",
            "%c0%ae%c0%ae%c0%afetc/passwd", "%e0%80%ae%e0%80%ae%e0%80%afsecret", "/a/..", "../secret\u0000.png", "..%255csecret"); }
    static Stream<String> benign() { return Stream.of("report.pdf", "/assets/app.js", "images/photo.png", "hello..world", "version...1", "/var/www/index.html", "C:\\Users\\Alice\\notes.txt", "windows", "etc/passwd", "a..b/c", "file%20name.txt", ".well-known/acme-challenge", "./relative.txt", "filename..", "a/b/c", "2026.10.25", "https://example.test/path", "backup.tar.gz", "שלום", "about.../"); }
}
