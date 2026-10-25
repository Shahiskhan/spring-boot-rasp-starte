package dev.rasp.core;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class InputNormalizerTest {
    @Test void handlesTwoEncodingLayersAndNeverChangesTheApplicationInput() {
        String original = "%253Cscript%253E";
        assertEquals("<script>", InputNormalizer.normalize(original));
        assertEquals("%253Cscript%253E", original);
        assertEquals("<script>", InputNormalizer.normalize("&amp;lt;SCRIPT&amp;gt;"));
        assertEquals("<script>", InputNormalizer.normalize("&#x3c;script&#62;"));
        assertEquals("<script>", InputNormalizer.normalize("\\u003cscript\\u003e"));
        assertEquals("java\t\n\rscript", InputNormalizer.normalize("java\u0000\u0001\t\n\r\u007f\u200b\ufeffscript"));
        assertEquals("café", InputNormalizer.normalize("CAF%C3%89"));
        assertEquals("a+b", InputNormalizer.normalize("A+B"));
        assertEquals("", InputNormalizer.normalize(null));
        assertEquals("", InputNormalizer.normalize(""));
    }
    @Test void decodesEntitiesWithoutThrowingOnMalformedOrOutOfRangeInput() {
        assertEquals("&\"':/", InputNormalizer.normalize("&amp;&quot;&apos;&colon;&sol;"));
        assertEquals("😀", InputNormalizer.normalize("&#128512;"));
        assertEquals("&#9999999999;", InputNormalizer.normalize("&#9999999999;"));
        assertEquals("&#xffffffff;", InputNormalizer.normalize("&#xffffffff;"));
        assertEquals("100% %zz %2", InputNormalizer.normalize("100% %zz %2"));
        assertEquals("&unknown;", InputNormalizer.normalize("&unknown;"));
        assertEquals("\\uzzzz", InputNormalizer.normalize("\\uZZZZ"));
        assertDoesNotThrow(() -> InputNormalizer.normalize("%c3%28%ff"));
    }
    @Test void recognizesOverlongSeparatorsForDetection() {
        assertEquals("../", InputNormalizer.normalize("%c0%ae%c0%ae%c0%af"));
        assertEquals("../", InputNormalizer.normalize("%e0%80%ae%e0%80%ae%e0%80%af"));
        assertEquals("..\\", InputNormalizer.normalize("..%c1%9c"));
        assertEquals("ab", InputNormalizer.normalize("a%c0%80b"));
    }
    @Test void contextualHtmlEncodingIsExplicit() {
        assertEquals("&lt;script&gt;", SafeOutput.forHtml("<script>"));
        assertEquals("", SafeOutput.forHtml(null));
        assertEquals("John", SafeOutput.forHtml("John"));
    }
}
