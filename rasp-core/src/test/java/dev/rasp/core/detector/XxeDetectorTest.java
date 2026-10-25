package dev.rasp.core.detector;

import static org.junit.jupiter.api.Assertions.*;
import dev.rasp.core.ScanContext;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class XxeDetectorTest {
    private final XxeDetector detector = new XxeDetector();
    @ParameterizedTest @MethodSource("attacks") void recognizesDeclarationsOnlyInXml(String value) {
        assertTrue(detector.detect(DetectorTestSupport.xml(value)).detected(), value);
    }
    @ParameterizedTest @MethodSource("benign") void acceptsXmlWithoutDeclarations(String value) {
        assertFalse(detector.detect(DetectorTestSupport.xml(value)).detected(), value);
    }
    @Test void requiresXmlBody() {
        assertFalse(detector.detect(DetectorTestSupport.query("<!DOCTYPE x>")).detected());
        var context = new ScanContext("POST", "/", Map.of("Content-Type", new String[]{"application/xml"}), Map.of(), null, Map.of(), null, "ip", "trace");
        assertFalse(detector.detect(context).detected());
        context = new ScanContext("POST", "/", Map.of("Content-Type", new String[]{"text/plain"}), Map.of(), "<!DOCTYPE x>", Map.of(), null, "ip", "trace");
        assertFalse(detector.detect(context).detected());
    }
    static Stream<String> attacks() { return Stream.of(
            "<!DOCTYPE x>", "<!doctype x>", "<! DOCTYPE x>", "<!ENTITY x 'value'>", "<!entity x SYSTEM 'file:///etc/passwd'>", "<!DOCTYPE x SYSTEM \"https://example.test/x.dtd\">",
            "<!DOCTYPE x [<!ENTITY x 'a'>]><x>&x;</x>", "SYSTEM 'file:///tmp/a'", "PUBLIC \"identifier\"", "<!DOCTYPE root PUBLIC 'x' 'y'>",
            "%3c!DOCTYPE%20x%3e", "&lt;!DOCTYPE x&gt;", "<?xml version='1.0'?><!DOCTYPE x><x/>", "<!ENTITY % x 'data'>"
    ); }
    static Stream<String> benign() { return Stream.of(
            "<user><name>John</name></user>", "<?xml version='1.0'?><root/>", "<root>DOCTYPE documentation</root>", "<system>public</system>", "<x>ENTITY</x>", "<a/>",
            "<text>&amp; &lt; &gt;</text>", "<data attr='x'>hello</data>", "<root><!-- safe comment --></root>", "<x><![CDATA[text]]></x>", "<items><item>1</item></items>",
            "<text>System administrator</text>", "<text>PUBLIC information</text>", "<x xmlns='urn:example:test'/>", "", "<根>文字</根>"
    ); }
}
