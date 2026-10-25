package dev.rasp.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.rasp.core.RaspBlockedException;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/** One response shape shared by the filter and MVC exception handling. */
final class RaspBlockResponse {
    private final RaspProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    RaspBlockResponse(RaspProperties properties) { this.properties = properties; }
    Map<String, Object> body(RaspBlockedException blocked) {
        var response = new LinkedHashMap<String, Object>();
        response.put("error", "BLOCKED");
        var result = blocked.getResult();
        String threat = result.engineError() ? "ENGINE_ERROR" : result.detections().isEmpty() ? "RATE_LIMIT" : "POLICY";
        if (properties.getResponse().isIncludeDetails() && !result.detections().isEmpty()) threat = result.detections().get(0).type().name();
        response.put("threat", threat);
        response.put("traceId", blocked.getTraceId());
        if (properties.getResponse().isIncludeDetails()) response.put("score", result.score());
        return response;
    }
    void write(HttpServletResponse response, RaspBlockedException blocked) throws IOException {
        if (response.isCommitted()) return;
        response.resetBuffer();
        response.setStatus(properties.getResponse().getHttpStatus());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        mapper.writeValue(response.getOutputStream(), body(blocked));
    }
}
