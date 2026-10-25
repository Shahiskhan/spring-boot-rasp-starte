package dev.rasp.autoconfigure;

import dev.rasp.core.RaspScan;
import dev.rasp.core.RaspBlockedException;
import dev.rasp.core.ScanContext;
import dev.rasp.core.ThreatType;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/** Scans explicitly annotated deserialized request objects; oversized raw bodies retain their configured exemption. */
@ControllerAdvice
@Order(0)
public final class RaspRequestBodyAdvice extends RequestBodyAdviceAdapter {
    private final RaspProperties properties;
    private final RaspInspectionService inspection;
    private final MethodArgumentScanner scanner;
    /** Constructs the rasp request body advice with its required collaborators. */
    public RaspRequestBodyAdvice(RaspProperties properties, RaspInspectionService inspection) {
        this.properties = properties; this.inspection = inspection; scanner = new MethodArgumentScanner(properties);
    }
    /** Provides the supports operation for the RASP integration. */
    @Override public boolean supports(MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return properties.getScan().isMethodArgs() && parameter.hasParameterAnnotation(RaspScan.class);
    }
    /** Provides the after body read operation for the RASP integration. */
    @Override public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
                                          Class<? extends HttpMessageConverter<?>> converterType) {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) return body;
        var request = attributes.getRequest();
        var state = RaspRequestState.of(request);
        if (state.exempt || state.oversized) return body;
        RaspScan annotation = parameter.getParameterAnnotation(RaspScan.class);
        if (annotation == null) return body;
        try {
            Map<String, String[]> values = scanner.extract("arg:" + parameter.getParameterName(), body, annotation.deepScan());
            ScanContext context = new ScanContext(request.getMethod(), "", Map.of(), values, null, Map.of(), new Object[0], request.getRemoteAddr(), state.traceId);
            inspection.inspect(context, request, Set.copyOf(Arrays.asList(annotation.types())));
        } catch (RaspBlockedException blocked) { throw blocked; }
        catch (RuntimeException extractionError) { inspection.extractionFailure(request); }
        return body;
    }
}
