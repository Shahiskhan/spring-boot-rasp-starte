package dev.rasp.core;

import static org.junit.jupiter.api.Assertions.*;
import dev.rasp.core.extract.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ExtractionTest {
    @Test void jsonParsesEscapesAndNestedArraysAndScansObjectKeys() {
        var payloads = new JsonBodyExtractor().extract("{\"users\":[{\"name\":\"\\u003cscript\\u003e\",\"age\":12}],\"$ne\":null,\"active\":true}");
        assertTrue(payloads.stream().anyMatch(p -> p.value().equals("<script>") && p.location().equals("body:$.users[0].name")));
        assertTrue(payloads.stream().anyMatch(p -> p.value().equals("$ne")));
        assertTrue(payloads.stream().anyMatch(p -> p.value().equals("12")));
        assertTrue(payloads.stream().anyMatch(p -> p.value().equals("true")));
        assertEquals(List.of(), new JsonBodyExtractor().extract(null));
        assertEquals(List.of(), new JsonBodyExtractor().extract("  "));
        assertEquals(List.of(), new JsonBodyExtractor().extract("null"));
        assertThrows(IllegalArgumentException.class, () -> new JsonBodyExtractor().extract("{bad-secret"));
    }
    @Test void formDecodesNamesValuesAndDuplicateFields() {
        var payloads = new FormBodyExtractor().extract("name=John+Doe&name=%3cscript%3e&empty&=value");
        assertTrue(payloads.contains(new Payload("form:name", "John Doe")));
        assertTrue(payloads.contains(new Payload("form:name", "<script>")));
        assertTrue(payloads.contains(new Payload("form:empty", "")));
        assertTrue(payloads.contains(new Payload("form:", "value")));
        assertEquals(List.of(), new FormBodyExtractor().extract(null));
        assertEquals(List.of(), new FormBodyExtractor().extract(""));
        assertThrows(IllegalArgumentException.class, () -> new FormBodyExtractor().extract("q=%not-valid"));
    }
    @Test void xmlExtractionNeverResolvesEntities() {
        String xml = "<!DOCTYPE x SYSTEM 'file:///sensitive'><x/>";
        assertEquals(List.of(new Payload("body:xml", xml)), new XmlBodyExtractor().extract(xml));
        assertEquals(List.of(), new XmlBodyExtractor().extract(null));
        assertEquals(List.of(), new XmlBodyExtractor().extract(""));
        assertFalse(new Payload("secret-key", "sensitive").toString().contains("sensitive"));
    }
    @Test void contextDefensivelyCopiesInputArraysAndHidesToString() {
        String[] values = {"John"}; Object[] args = {"Alice"};
        var headers = new LinkedHashMap<String,String[]>(); headers.put("X-Name", values); headers.put("X-Null", null);
        var context = new ScanContext("GET", "/", headers, Map.of("name", values), "secret-body", null, args, "192.0.2.1", "trace");
        values[0] = "mutated"; args[0] = "mutated";
        assertEquals("John", context.params().get("name")[0]);
        assertEquals("John", context.headers().get("X-Name")[0]);
        assertEquals(0, context.headers().get("X-Null").length);
        assertEquals("Alice", context.methodArgs()[0]);
        context.params().get("name")[0] = "modified";
        context.methodArgs()[0] = "modified";
        assertEquals("John", context.params().get("name")[0]);
        assertEquals("Alice", context.methodArgs()[0]);
        assertThrows(UnsupportedOperationException.class, () -> context.headers().put("new", values));
        assertFalse(context.toString().contains("secret-body"));
        assertEquals(Map.of(), context.bodyAsMap());
    }
    @Test void extractsAllProvidedSurfacesAndPrefersFilteredJson() {
        var context = new ScanContext("POST", "/api/a", Map.of("Content-Length", new String[]{"99"}, "X-Custom", new String[]{"hello"}),
                Map.of("q", new String[]{"world"}), "unfiltered-secret", Map.of("filtered", "allowed"), new Object[]{"argument"}, "ip", "trace");
        var payloads = ScanPayloads.from(context);
        assertTrue(payloads.contains(new Payload("uri", "/api/a")));
        assertTrue(payloads.contains(new Payload("header:X-Custom", "hello")));
        assertTrue(payloads.contains(new Payload("param:q", "world")));
        assertTrue(payloads.contains(new Payload("body:$.filtered", "allowed")));
        assertTrue(payloads.contains(new Payload("arg:0", "argument")));
        assertFalse(payloads.stream().anyMatch(p -> p.value().equals("unfiltered-secret")));
        var optedInHeaders = new ScanContext("GET", "/", Map.of("Cookie",new String[]{"<script>"}), Map.of(), null, Map.of(), null, "ip", "trace");
        assertTrue(ScanPayloads.from(optedInHeaders).contains(new Payload("header:Cookie", "<script>")));
    }
    @Test void dispatchesRawBodiesByContentTypeAndHandlesEmptyInputs() {
        assertTrue(ScanPayloads.from(raw("application/json", "{\"x\":\"hello\"}")).contains(new Payload("body:$.x", "hello")));
        assertTrue(ScanPayloads.from(raw("application/json", "{\"x\":\"<script>\"")).contains(new Payload("body:raw", "{\"x\":\"<script>\"")));
        assertTrue(ScanPayloads.from(raw("application/x-www-form-urlencoded", "x=hello")).contains(new Payload("form:x", "hello")));
        assertTrue(ScanPayloads.from(raw("application/xml", "<x/>")).contains(new Payload("body:xml", "<x/>")));
        assertTrue(ScanPayloads.from(raw("text/plain", "hello")).contains(new Payload("body:raw", "hello")));
        assertEquals("application/xml", ScanPayloads.contentType(raw("APPLICATION/XML", "")));
        assertEquals(List.of(), ScanPayloads.from(new ScanContext(null, null, null, null, null, null, null, null, null)));
    }
    @Test void handlesPrimitiveArraysCyclesUnknownObjectsAndSafetyLimits() {
        var output = new ArrayList<Payload>();
        var map = new LinkedHashMap<Object,Object>(); map.put("array", new int[]{1,2}); map.put(99, "ignored-key"); map.put("self", map);
        ScanPayloads.flatten("arg", map, output);
        assertTrue(output.contains(new Payload("arg.array[0]", "1")));
        assertTrue(output.contains(new Payload("arg.array[1]", "2")));
        ScanPayloads.flatten("arg", new Object(){ @Override public String toString() { throw new AssertionError("Do not invoke arbitrary DTO methods"); } }, output);
        ScanPayloads.flatten("arg", ThreatType.XSS, output);
        ScanPayloads.flatten("arg", 'a', output);
        ScanPayloads.flatten("arg", true, output);
        assertTrue(output.contains(new Payload("arg", "XSS")));
        Object nested = "value";
        for (int i=0; i<34; i++) nested = List.of(nested);
        Object tooDeep = nested;
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.flatten("arg", tooDeep, new ArrayList<>()));
        var tooMany = new ArrayList<Payload>();
        for (int i=0; i<8192; i++) tooMany.add(new Payload("x", "y"));
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.flatten("arg", "x", tooMany));
        String[] huge = new String[8200]; java.util.Arrays.fill(huge, "safe");
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.from(new ScanContext("GET", "/", null, Map.of("x",huge), null,null,null,null,null)));
        Map<String,Object> nullMap = new LinkedHashMap<>();
        for (int i=0; i<9000; i++) nullMap.put("key" + i, null);
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.flatten("arg", nullMap, new ArrayList<>()));
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.flatten("arg", java.util.Collections.nCopies(9000, null), new ArrayList<>()));
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.flatten("arg", new Object[9000], new ArrayList<>()));
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.from(new ScanContext("GET", "/", null, Map.of("x",new String[9000]), null,null,null,null,null)));
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.from(new ScanContext("GET", "/", Map.of("X-Null",new String[9000]), null, null,null,null,null,null)));
        assertThrows(IllegalArgumentException.class, () -> ScanPayloads.from(new ScanContext("GET", "/", null, null, null,null,new Object[9000],null,null)));
    }
    private ScanContext raw(String contentType, String body) {
        return new ScanContext("POST", "/", Map.of("cOnTeNt-TyPe", new String[]{contentType}), Map.of(), body, Map.of(), null, "ip", "trace");
    }
}
