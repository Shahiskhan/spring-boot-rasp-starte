package dev.rasp.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/** Request surfaces to scan. Integrations remove whitelisted fields before constructing this value. */
public record ScanContext(String httpMethod, String uri, Map<String,String[]> headers,
        Map<String,String[]> params, String rawBody, Map<String,Object> bodyAsMap,
        Object[] methodArgs, String clientIp, String traceId) {
    public ScanContext {
        headers = copyArrays(headers);
        params = copyArrays(params);
        bodyAsMap = bodyAsMap == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(bodyAsMap));
        methodArgs = methodArgs == null ? new Object[0] : methodArgs.clone();
    }

    private static Map<String,String[]> copyArrays(Map<String,String[]> source) {
        if (source == null || source.isEmpty()) return Map.of();
        Map<String,String[]> result = new LinkedHashMap<>();
        source.forEach((key, value) -> result.put(key, value == null ? new String[0] : value.clone()));
        return Collections.unmodifiableMap(result);
    }

    /** Defensive copy of header arrays. */
    @Override public Map<String,String[]> headers() { return copyArrays(headers); }
    /** Defensive copy of query/form arrays. */
    @Override public Map<String,String[]> params() { return copyArrays(params); }
    /** Defensive copy of method arguments. Nested DTOs must not be mutated during a scan. */
    @Override public Object[] methodArgs() { return methodArgs.clone(); }
    /** Prevent accidental raw request data disclosure in logs. */
    @Override public String toString() { return "ScanContext[request metadata and payloads redacted]"; }
}
