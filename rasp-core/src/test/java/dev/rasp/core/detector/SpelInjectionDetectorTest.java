package dev.rasp.core.detector;

import static org.junit.jupiter.api.Assertions.*;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class SpelInjectionDetectorTest {
    private final SpelInjectionDetector detector = new SpelInjectionDetector();
    @ParameterizedTest @MethodSource("attacks") void recognizesExecutionSyntax(String value) {
        assertTrue(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    @ParameterizedTest @MethodSource("benign") void acceptsNormalTemplatesAndJson(String value) {
        assertFalse(detector.detect(DetectorTestSupport.query(value)).detected(), value);
    }
    static Stream<String> attacks() { return Stream.of(
            "T(java.lang.Runtime).getRuntime().exec('id')", "T ( java.lang.Runtime )", "t(java.lang.ProcessBuilder)", "T(java.lang.System).getenv()",
            "T(java.nio.file.Files)", "foo.getClass()", "Class.forName('java.lang.Runtime')", "getRuntime ()", "x.exec('id')", "x.invoke(y)",
            "x.newInstance()", "java.lang.ClassLoader", "javax.script.ScriptEngineManager", "#{7*7}", "${7*7}", "#{1+1}", "${'a'+'b'}",
            "#{new java.lang.String('x')}", "#{T(java.lang.Runtime)}", "eval('x')", "%54%28java.lang.Runtime%29", "get\\u0043lass()",
            "GETCLASS ( )", "${x/y}", "#{x==y}", "claſſloader", "scrıptenginemanager"
    ); }
    static Stream<String> benign() { return Stream.of(
            "John", "{\"name\":\"John\"}", "{ nested: { value: 1 } }", "${name}", "#{name}", "${spring.profiles.active}", "T-shirt",
            "getClass documentation", "forName", "getRuntime statistics", "execute task", "invoker", "newInstance documentation", "class loaders",
            "runtime monitor", "System administrator", "process builder", "{name}", "$10", "7*7", "name=value", "evaluation", "#{abc.def}",
            "[1,2,3]", "https://example.test/?a=b", "users@example.test", "普通文本", "regular expression [a-z]+", "ſcriptenginemanager"
    ); }
}
