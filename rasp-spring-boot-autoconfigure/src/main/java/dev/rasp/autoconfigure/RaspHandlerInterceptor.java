package dev.rasp.autoconfigure;

import dev.rasp.core.RaspBlockedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.util.WebUtils;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Scans resolved path variables and multipart names after MVC has resolved request metadata. */
final class RaspHandlerInterceptor implements HandlerInterceptor {
    private final RaspInspectionService inspection;
    private final RequestPayloadExtractor extractor;
    private final RaspProperties properties;
    RaspHandlerInterceptor(RaspInspectionService inspection, RaspProperties properties) {
        this.inspection = inspection; this.properties = properties; extractor = new RequestPayloadExtractor(properties);
    }
    /** Provides the pre handle operation for the RASP integration. */
    @Override public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        try { return scanMetadata(request, handler); }
        catch (RaspBlockedException blocked) { throw blocked; }
        catch (RuntimeException extractionError) { inspection.extractionFailure(request); return true; }
    }
    private boolean scanMetadata(HttpServletRequest request, Object handler) {
        RaspRequestState state = RaspRequestState.of(request);
        if (state.exempt) return true;
        var values = new LinkedHashMap<String, String[]>();
        CachedBodyRequest cached = WebUtils.getNativeRequest(request, CachedBodyRequest.class);
        if (cached != null && cached.isDeferredForm()) {
            // Spring's POST form converter uses servlet parameters only when there is no query string.
            // With a query string (or explicit servlet stream access), preserve the original raw stream instead.
            if (usesServletFormParameters(request, handler)) {
                Map<String, String[]> parsed = request.getParameterMap();
                long bytes = 0;
                for (Map.Entry<String, String[]> entry : parsed.entrySet()) {
                    bytes += entry.getKey().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                    for (String value : entry.getValue()) bytes += value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                }
                state.oversized = bytes > properties.getScan().getMaxBodySize().toBytes();
                if (!state.oversized) parsed.forEach((key, entries) -> { if (!extractor.excludedParameter(key)) values.put("body:" + key, entries); });
            } else {
                cached.bufferDeferredBody(Math.toIntExact(properties.getScan().getMaxBodySize().toBytes()));
                state.oversized = cached.isOversized();
                if (cached.failure() != null) inspection.extractionFailure(request);
                inspection.inspect(extractor.extract(cached), request, Set.of());
            }
        }
        if (properties.getScan().isUri()) {
            Object variables = request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
            if (variables instanceof Map<?, ?> map) map.forEach((key, value) -> values.put("path:" + key, new String[] {String.valueOf(value)}));
        }
        if (properties.getScan().isBody() && request instanceof MultipartHttpServletRequest multipart) {
            multipart.getMultiFileMap().forEach((key, files) -> {
                if (!extractor.excludedParameter(key)) values.put("file:" + key, files.stream().map(MultipartFile::getOriginalFilename).toArray(String[]::new));
            });
            if (properties.getScan().isQueryParams()) multipart.getParameterMap().forEach((key, value) -> {
                if (!extractor.excludedParameter(key)) values.put(key, value);
            });
        }
        if (!values.isEmpty()) inspection.inspect(extractor.extra(request, values), request, Set.of());
        return true;
    }
    private static boolean usesServletFormParameters(HttpServletRequest request, Object handler) {
        if (!(handler instanceof HandlerMethod method)) return false;
        var parameters = java.util.Arrays.asList(method.getMethodParameters());
        boolean messageBody = parameters.stream().anyMatch(parameter -> parameter.hasParameterAnnotation(RequestBody.class)
                || org.springframework.http.HttpEntity.class.isAssignableFrom(parameter.getParameterType()));
        if (messageBody) return "POST".equals(request.getMethod()) && request.getQueryString() == null;
        boolean boundForm = parameters.stream().anyMatch(parameter -> parameter.hasParameterAnnotation(RequestParam.class)
                || parameter.hasParameterAnnotation(ModelAttribute.class));
        if (boundForm) return true;
        return parameters.stream().noneMatch(parameter -> jakarta.servlet.ServletRequest.class.isAssignableFrom(parameter.getParameterType())
                || java.io.InputStream.class.isAssignableFrom(parameter.getParameterType())
                || java.io.Reader.class.isAssignableFrom(parameter.getParameterType()));
    }
}
