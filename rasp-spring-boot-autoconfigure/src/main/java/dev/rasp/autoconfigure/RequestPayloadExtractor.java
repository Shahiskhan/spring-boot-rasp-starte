package dev.rasp.autoconfigure;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rasp.core.ScanContext;
import jakarta.servlet.http.HttpServletRequest;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Extracts surfaces without invoking servlet form parsing before the replay wrapper is installed. */
final class RequestPayloadExtractor {
    private final RaspProperties properties;
    private final ObjectMapper mapper;
    RequestPayloadExtractor(RaspProperties properties) {
        this.properties = properties;
        mapper = new ObjectMapper();
        mapper.getFactory().setStreamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(64).build());
    }
    ScanContext extract(HttpServletRequest request) {
        var headers = new LinkedHashMap<String, String[]>();
        if (properties.getScan().isHeaders()) {
            Enumeration<String> names = request.getHeaderNames();
            if (names != null) while (names.hasMoreElements()) {
                String name = names.nextElement();
                if (!excludedHeader(name)) {
                    var values = Collections.list(request.getHeaders(name));
                    headers.put(stripControls(name), values.stream().map(RequestPayloadExtractor::stripControls).toArray(String[]::new));
                }
            }
        }
        // The XXE detector needs the media type even when ordinary header scanning is disabled.
        if (request.getContentType() != null) headers.put("Content-Type", new String[] {stripControls(request.getContentType())});
        Map<String, String[]> parameters = properties.getScan().isQueryParams()
                ? filtered(parseForm(request.getQueryString())) : new LinkedHashMap<>();
        String rawBody = null;
        Map<String, Object> structured = new LinkedHashMap<>();
        if (request instanceof CachedBodyRequest cached && cached.isBuffered()) {
            String body = cached.bodyText();
            String contentType = mediaType(request.getContentType());
            if (contentType.equals("application/x-www-form-urlencoded")) {
                Map<String, String[]> form = parseForm(body);
                Map<String, String[]> all = parseForm(request.getQueryString());
                merge(all, form);
                // The servlet container binds form bodies only for POST. Spring's FormContentFilter owns other verbs.
                if ("POST".equals(request.getMethod())) cached.setFormParameters(all);
                filtered(form).forEach((key, values) -> append(parameters, "body:" + key, values));
            } else if (contentType.endsWith("json") || contentType.endsWith("+json")) {
                try {
                    Object decoded = mapper.readValue(body, Object.class);
                    Object sanitized = removeWhitelisted(decoded, 0);
                    if (sanitized instanceof Map<?, ?> map) map.forEach((key, value) -> structured.put(String.valueOf(key), value));
                    else structured.put("$", sanitized);
                } catch (JsonProcessingException invalidJson) {
                    // Scan malformed JSON as text; the application's normal message converter will reject it later.
                    rawBody = body;
                }
            } else rawBody = body;
        }
        RaspRequestState state = RaspRequestState.of(request);
        return new ScanContext(request.getMethod(), properties.getScan().isUri() ? request.getRequestURI() : "",
                headers, parameters, rawBody, structured, new Object[0], request.getRemoteAddr(), state.traceId);
    }
    ScanContext extra(HttpServletRequest request, Map<String, String[]> parameters) {
        return new ScanContext(request.getMethod(), "", Map.of(), filtered(parameters), null, Map.of(), new Object[0], request.getRemoteAddr(), RaspRequestState.of(request).traceId);
    }
    boolean scanBody(HttpServletRequest request) {
        if (!properties.getScan().isBody()) return false;
        String type = mediaType(request.getContentType());
        if (properties.getScan().getSkipContentTypes().stream().anyMatch(skip -> type.equalsIgnoreCase(mediaType(skip)))) return false;
        // Do not read an absent GET/HEAD entity, but scan an entity explicitly supplied for any method.
        return !(List.of("GET", "HEAD").contains(request.getMethod())
                && request.getContentLengthLong() <= 0 && request.getHeader("Transfer-Encoding") == null);
    }
    boolean excludedParameter(String name) { return properties.getWhitelist().getParamNames().contains(name); }
    private boolean excludedHeader(String name) { return properties.getWhitelist().getHeaders().stream().anyMatch(name::equalsIgnoreCase); }
    private Map<String, String[]> filtered(Map<String, String[]> source) {
        var result = new LinkedHashMap<String, String[]>();
        source.forEach((key, value) -> { if (!excludedParameter(key)) result.put(key, value); });
        return result;
    }
    private Object removeWhitelisted(Object value, int depth) {
        if (depth > 64) throw new IllegalArgumentException("JSON nesting exceeds extraction limit");
        if (value instanceof Map<?, ?> map) {
            var result = new LinkedHashMap<String, Object>();
            map.forEach((key, child) -> {
                String name = String.valueOf(key);
                if (!excludedParameter(name)) result.put(name, removeWhitelisted(child, depth + 1));
            });
            return result;
        }
        if (value instanceof List<?> list) return list.stream().map(child -> removeWhitelisted(child, depth + 1)).toList();
        return value;
    }
    static Map<String, String[]> parseForm(String encoded) {
        var result = new LinkedHashMap<String, String[]>();
        if (encoded == null || encoded.isEmpty()) return result;
        for (String pair : encoded.split("&", -1)) {
            if (pair.isEmpty()) continue;
            int equals = pair.indexOf('=');
            String key = URLDecoder.decode(equals < 0 ? pair : pair.substring(0, equals), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(equals < 0 ? "" : pair.substring(equals + 1), StandardCharsets.UTF_8);
            append(result, key, new String[] {value});
        }
        return result;
    }
    private static void merge(Map<String, String[]> into, Map<String, String[]> from) { from.forEach((key, value) -> append(into, key, value)); }
    private static void append(Map<String, String[]> map, String key, String[] values) {
        var combined = new ArrayList<String>();
        if (map.containsKey(key)) Collections.addAll(combined, map.get(key));
        Collections.addAll(combined, values);
        map.put(key, combined.toArray(String[]::new));
    }
    static String mediaType(String contentType) {
        return contentType == null ? "" : contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
    }
    static String stripControls(String value) {
        if (value == null) return "";
        var safe = new StringBuilder(value.length());
        value.codePoints().filter(c -> c >= 32 && c != 127).forEach(safe::appendCodePoint);
        return safe.toString();
    }
}
