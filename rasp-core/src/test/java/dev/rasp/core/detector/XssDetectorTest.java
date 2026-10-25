package dev.rasp.core.detector;

import static org.junit.jupiter.api.Assertions.*;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class XssDetectorTest {
    private final XssDetector detector = new XssDetector();
    @ParameterizedTest @MethodSource("attacks") void recognizesActiveMarkup(String value) {
        assertTrue(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    @ParameterizedTest @MethodSource("benign") void acceptsTextAndOrdinaryMarkup(String value) {
        assertFalse(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    static Stream<String> attacks() { return Stream.of(
            "<script>alert(1)</script>", "<SCRIPT SRC=x>", "<script", "</script>", "< script >",
            "<img src=x onerror=alert(1)>", "<svg onload = alert(1)>", "onclick=run()", "onmouseover =run()", "onfocus=run()",
            "onanimationstart=run()", "onpointerenter=run()", "onmouseenter=run()", "ontoggle=run()", "onsubmit=run()",
            "javascript:alert(1)", "JaVaScRiPt :alert(1)", "java\nscript:alert(1)", "vbscript:msgbox(1)", "data:text/html,<h1>x</h1>",
            "data: application/xhtml+xml,x", "<iframe src=x>", "<OBJECT data=x>", "<embed src=x>", "document.cookie", "document.write('x')",
            "document . location", "eval('1')", "eval ('1')", "%3Cscript%3Ealert(1)", "%253Cscript%253Ealert(1)",
            "&lt;script&gt;alert(1)", "&amp;lt;script&amp;gt;", "&#60;script&#62;", "&#x3c;script&#x3e;", "\\u003cscript\\u003e",
            "<scr\u0000ipt>alert(1)", "javascript&colon;alert(1)"
    ); }
    static Stream<String> benign() { return Stream.of(
            "John", "<p>hello</p>", "<strong>bold</strong>", "<div class=note>hello</div>", "5 < 7 and 8 > 2", "<svg viewBox='0 0 1 1'>",
            "description of a script", "typescript", "<scripture>", "onload", "onclick handler docs", "application/json", "https://example.test",
            "data:image/png;base64,iVBORw0KGgo=", "mail@example.test", "{\"message\":\"hello\"}", "document.title", "evaluation", "evaluator(1)",
            "hello & goodbye", "&copy; 2026", "plain (parentheses)", "query?x=1&y=2", "${name}", "#{name}", "^([a-z]+)$",
            "café", "用户", "<img src='/photo.png' alt='Photo'>", "<a href='https://example.test'>link</a>"
    ); }
}
