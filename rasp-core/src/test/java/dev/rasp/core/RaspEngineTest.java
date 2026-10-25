package dev.rasp.core;

import static org.junit.jupiter.api.Assertions.*;
import dev.rasp.core.detector.*;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class RaspEngineTest {
    static List<ThreatDetector> detectors() {
        PatternCache cache = new PatternCache();
        return List.of(new SqlInjectionDetector(cache), new XssDetector(cache), new SpelInjectionDetector(cache),
                new PathTraversalDetector(cache), new CommandInjectionDetector(cache), new LdapInjectionDetector(cache),
                new NoSqlInjectionDetector(cache), new XxeDetector(cache));
    }
    static ScanContext query(String value) {
        return new ScanContext("GET", "/api/search", Map.of(), Map.of("q", new String[]{value}), null, Map.of(), null, "192.0.2.1", "trace");
    }
    @Test void blocksAllThreatFamiliesAndKeepsCleanRequests() {
        var engine = new RaspEngine(detectors(), RaspMode.BLOCK, true, 50);
        for (String value : List.of("' OR 1=1--", "<script>", "T(java.lang.Runtime)", "../secret", ";whoami", "*))", "$ne")) {
            assertTrue(engine.scan(query(value)).blocked(), value);
        }
        assertEquals(ScanResult.allowed(), engine.scan(query("John")));
        var xml = new ScanContext("POST", "/xml", Map.of("Content-Type", new String[]{"application/xml"}), Map.of(), "<!DOCTYPE x>", Map.of(), null, "ip", "trace");
        assertEquals(100, engine.scan(xml).score());
    }
    @Test void monitorAndConfidenceThresholdLogWithoutBlocking() {
        assertEquals(Decision.LOG, new RaspEngine(detectors(), RaspMode.MONITOR, true, 50).scan(query("<script>")).decision());
        assertEquals(Decision.LOG, new RaspEngine(detectors(), RaspMode.BLOCK, true, 99).scan(query("<script>")).decision());
        assertTrue(new RaspEngine(detectors(), RaspMode.STRICT, true, 50).scan(query("<script>")).blocked());
    }
    @Test void selectsAnnotationThreatTypesWithoutSkippingUnselectedRequests() {
        var engine = new RaspEngine(detectors(), RaspMode.BLOCK, true, 50);
        assertEquals(Decision.ALLOW, engine.scan(query("<script>"), Set.of(ThreatType.SQLI)).decision());
        assertTrue(engine.scan(query("<script>"), Set.of(ThreatType.XSS)).blocked());
        assertThrows(NullPointerException.class, () -> engine.scan(null));
        assertThrows(NullPointerException.class, () -> engine.scan(query("safe"), null));
        assertEquals(Decision.ALLOW,engine.scan(query("<!DOCTYPE x>"),Set.of(ThreatType.XXE)).decision());
        var plain=new ScanContext("POST","/",Map.of("Content-Type",new String[]{"text/plain"}),Map.of(),"<!DOCTYPE x>",Map.of(),null,"ip","trace");
        assertEquals(Decision.ALLOW,engine.scan(plain,Set.of(ThreatType.XXE)).decision());
    }
    @Test void policyOnDetectorFailureIsExplicitAndOtherDetectorsStillRun() {
        ThreatDetector faulty = new ThreatDetector() {
            public DetectionResult detect(ScanContext context) { throw new IllegalStateException("secret-untrusted-input"); }
            public ThreatType getType() { return ThreatType.SQLI; }
            public int getPriority() { return 999; }
        };
        var list = List.of(faulty, new XssDetector());
        var open = new RaspEngine(list, RaspMode.BLOCK, true, 50).scan(query("safe"));
        assertTrue(open.engineError());
        assertEquals(Decision.LOG, open.decision());
        assertFalse(open.toString().contains("secret-untrusted-input"));
        var closed = new RaspEngine(list, RaspMode.BLOCK, false, 50).scan(query("safe"));
        assertTrue(closed.blocked());
        assertTrue(new RaspEngine(list, RaspMode.BLOCK, true, 50).scan(query("<script>")).blocked());
    }
    @Test void nullDetectorResultIsTreatedAsEngineError() {
        ThreatDetector faulty = org.mockito.Mockito.mock(ThreatDetector.class);
        org.mockito.Mockito.when(faulty.getType()).thenReturn(ThreatType.SQLI);
        assertTrue(new RaspEngine(List.of(faulty), RaspMode.BLOCK, false, 50).scan(query("safe")).blocked());
    }
    @Test void customSpiKeepsOriginalContextAndDoesNotRequireBuiltinExtraction() {
        var context = new ScanContext("POST", "/", null, null, null, null, new Object[9000], "ip", "trace");
        ThreatDetector custom = new ThreatDetector() {
            public DetectionResult detect(ScanContext received) { assertSame(context, received); return DetectionResult.clean(ThreatType.SQLI); }
            public ThreatType getType() { return ThreatType.SQLI; }
            public int getPriority() { return 1; }
        };
        assertFalse(custom.usesPreparedPayloads());
        assertEquals(DetectionResult.clean(ThreatType.SQLI), custom.detectPrepared(context, List.of()));
        assertEquals(ScanResult.allowed(), new RaspEngine(List.of(custom), RaspMode.BLOCK, false, 50).scan(context));
    }
    @Test void preparationFailureIsReportedButDoesNotSuppressCustomStrategies() {
        var context = new ScanContext("POST", "/", null, null, null, null, new Object[9000], "ip", "trace");
        ThreatDetector custom = new ThreatDetector() {
            public DetectionResult detect(ScanContext received) { return new DetectionResult(ThreatType.SQLI,true,90,"","custom"); }
            public ThreatType getType() { return ThreatType.SQLI; }
            public int getPriority() { return -1; }
        };
        var result = new RaspEngine(List.of(new XssDetector(), new SpelInjectionDetector(), custom),RaspMode.BLOCK,true,50).scan(context);
        assertTrue(result.engineError());
        assertTrue(result.blocked());
        assertEquals(1,result.detections().size());
    }
    @Test void preparedPayloadsAreDecodedExactlyTwiceAndSharedAcrossBuiltinStrategies() {
        var engine = new RaspEngine(detectors(),RaspMode.BLOCK,true,50);
        assertTrue(engine.scan(query("%253Cscript%253E")).blocked());
        assertFalse(engine.scan(query("%25253Cscript%25253E")).blocked(),"Prepared values must not be decoded a third time by each detector");
        assertEquals("<script>",dev.rasp.core.extract.ScanPayloads.normalizedFrom(query("%253Cscript%253E")).stream()
                .filter(p -> p.location().equals("param:q")).findFirst().orElseThrow().value());
    }
    @Test void sharedEngineIsSafeUnderConcurrentRequests() throws Exception {
        var engine = new RaspEngine(detectors(), RaspMode.BLOCK, true, 50);
        var pool = Executors.newFixedThreadPool(8);
        try {
            var futures = IntStream.range(0, 400).mapToObj(i -> pool.submit(() -> engine.scan(query(i % 2 == 0 ? "<script>" : "John")))).toList();
            for (int i = 0; i < futures.size(); i++) assertEquals(i % 2 == 0, futures.get(i).get(10, TimeUnit.SECONDS).blocked());
            assertTrue(engine.scanAsync(query("<script>"), pool).get(5, TimeUnit.SECONDS).blocked());
        } finally { pool.shutdownNow(); }
        assertThrows(NullPointerException.class, () -> engine.scanAsync(query("x"), null));
    }
    @Test void scorerUsesStrongestFindingRatherThanAmplifyingWeakOnes() {
        assertEquals(0, new ThreatScorer().score(List.of(DetectionResult.clean(ThreatType.XSS))));
        assertEquals(60, new ThreatScorer().score(List.of(new DetectionResult(ThreatType.XSS, true, 30, "", ""), new DetectionResult(ThreatType.SQLI, true, 60, "", ""))));
    }
    @Test void validatesModelsAndKeepsDiagnosticStringsPrivate() {
        assertThrows(IllegalArgumentException.class, () -> new DetectionResult(ThreatType.SQLI, true, 101, "", ""));
        assertThrows(IllegalArgumentException.class, () -> new DetectionResult(ThreatType.SQLI, true, -1, "", ""));
        assertThrows(NullPointerException.class, () -> DetectionResult.clean(null));
        var finding = new DetectionResult(ThreatType.SQLI, true, 90, "sensitive", "secret-location");
        assertFalse(finding.toString().contains("sensitive"));
        assertFalse(finding.toString().contains("secret-location"));
        assertEquals("", new DetectionResult(ThreatType.XSS, false, 0, null, null).evidence());
        assertEquals("", new DetectionResult(ThreatType.XSS, false, 0, null, null).location());
        var result = new ScanResult(new ArrayList<>(List.of(finding)), 90, Decision.BLOCK, false);
        assertThrows(UnsupportedOperationException.class, () -> result.detections().clear());
        assertThrows(IllegalArgumentException.class, () -> new ScanResult(List.of(), 101, Decision.ALLOW, false));
        assertThrows(IllegalArgumentException.class, () -> new ScanResult(List.of(), -1, Decision.ALLOW, false));
        assertThrows(NullPointerException.class, () -> new ScanResult(List.of(), 0, null, false));
        var exception = new RaspBlockedException(result, "trace-id");
        assertEquals(result, exception.result()); assertEquals(result, exception.getResult());
        assertEquals("trace-id", exception.traceId()); assertEquals("trace-id", exception.getTraceId());
        assertFalse(exception.getMessage().contains("sensitive"));
        assertEquals("", new RaspBlockedException(result, null).traceId());
    }
    @Test void validatesPolicyAndCacheConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new PolicyEngine(RaspMode.BLOCK, true, 0));
        assertThrows(IllegalArgumentException.class, () -> new PolicyEngine(RaspMode.BLOCK, true, 101));
        assertThrows(NullPointerException.class, () -> new PolicyEngine(null, true, 50));
        assertEquals(Decision.ALLOW, new PolicyEngine(RaspMode.BLOCK, false, 50).decide(0, false));
        assertEquals(Decision.BLOCK, new PolicyEngine(RaspMode.MONITOR, false, 50).decide(0, true));
        assertThrows(IllegalArgumentException.class, () -> new PatternCache(0, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new PatternCache(1, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new PatternCache(1, Duration.ofSeconds(-1)));
        assertThrows(NullPointerException.class, () -> new PatternCache(1, null));
        var cache = new PatternCache(5, Duration.ofMinutes(1));
        assertSame(cache.compile("hello"), cache.compile("hello"));
        assertTrue(cache.compile("hello.world").matcher("HELLO\nWORLD").find());
        assertThrows(NullPointerException.class, () -> cache.compile(null));
    }
}
