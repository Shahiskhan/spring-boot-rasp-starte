package dev.rasp.autoconfigure;

import org.owasp.encoder.Encode;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/** Applies OWASP HTML-content encoding only to opted-in HTML String responses; JSON and other contexts are untouched. */
@ControllerAdvice
public final class RaspResponseBodyAdvice implements ResponseBodyAdvice<String> {
    /** Provides the supports operation for the RASP integration. */
    @Override public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return returnType.hasMethodAnnotation(RaspEncodeHtml.class) && String.class == returnType.getParameterType();
    }
    /** Provides the before body write operation for the RASP integration. */
    @Override public String beforeBodyWrite(String body, MethodParameter returnType, MediaType contentType,
                                            Class<? extends HttpMessageConverter<?>> converterType,
                                            ServerHttpRequest request, ServerHttpResponse response) {
        return body != null && MediaType.TEXT_HTML.isCompatibleWith(contentType) ? Encode.forHtmlContent(body) : body;
    }
}
