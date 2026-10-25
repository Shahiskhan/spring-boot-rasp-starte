package dev.rasp.autoconfigure;

import dev.rasp.core.RaspBlockedException;
import dev.rasp.core.RaspEngine;
import dev.rasp.core.RaspMode;
import dev.rasp.core.detector.XssDetector;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.unit.DataSize;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestExtractionTest {
    @Test void fullyBufferedBodySupportsReaderAndReadListener() throws Exception {
        var request = body("hello", "text/plain");
        var wrapped = new CachedBodyRequest(request, 5);
        assertThat(wrapped.isBuffered()).isTrue(); assertThat(wrapped.isOversized()).isFalse(); assertThat(wrapped.failure()).isNull();
        assertThat(wrapped.bodyText()).isEqualTo("hello");
        var stream = wrapped.getInputStream();
        assertThat(stream.isReady()).isTrue(); assertThat(stream.isFinished()).isFalse(); assertThat(stream.available()).isEqualTo(5);
        var callbacks = new AtomicInteger();
        stream.setReadListener(new ReadListener() {
            @Override public void onDataAvailable() throws IOException { assertThat(stream.readAllBytes()).isEqualTo("hello".getBytes(StandardCharsets.UTF_8)); callbacks.incrementAndGet(); }
            @Override public void onAllDataRead() { callbacks.incrementAndGet(); }
            @Override public void onError(Throwable error) { throw new AssertionError(error); }
        });
        assertThat(callbacks).hasValue(2); assertThat(stream.isFinished()).isTrue();
        assertThatThrownBy(() -> stream.setReadListener(null)).isInstanceOf(IllegalArgumentException.class);
        stream.close();
        var reader = new CachedBodyRequest(body("unicode café", "text/plain;charset=UTF-8"), 100).getReader();
        assertThat(reader.readLine()).isEqualTo("unicode café");
    }
    @Test void knownAndUnknownOversizedBodiesAreReplayedInFull() throws Exception {
        for (boolean unknown : List.of(true, false)) {
            MockHttpServletRequest request = unknown ? new UnknownLengthRequest() : new MockHttpServletRequest();
            request.setContent("0123456789".getBytes(StandardCharsets.UTF_8));
            var wrapped = new CachedBodyRequest(request, 4);
            assertThat(wrapped.isBuffered()).isFalse(); assertThat(wrapped.isOversized()).isTrue();
            assertThat(wrapped.bodyText()).isNull();
            assertThat(new String(wrapped.getInputStream().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo("0123456789");
        }
    }
    @Test void emptyBodyIsReplayable() throws Exception {
        var wrapped = new CachedBodyRequest(body("", "text/plain"), 10);
        assertThat(wrapped.isBuffered()).isTrue(); assertThat(wrapped.getInputStream().isFinished()).isTrue();
        assertThat(wrapped.getInputStream().read()).isEqualTo(-1);
    }
    @Test void formParameterViewsCannotMutateReplayState() {
        var wrapper = new CachedBodyRequest(body("a=1&a=2", "application/x-www-form-urlencoded"), 100);
        wrapper.setFormParameters(Map.of("a", new String[] {"1", "2"}));
        assertThat(wrapper.getParameter("a")).isEqualTo("1"); assertThat(wrapper.getParameter("missing")).isNull();
        assertThat(wrapper.getParameterValues("missing")).isNull();
        String[] values = wrapper.getParameterValues("a"); values[0] = "corrupt";
        wrapper.getParameterMap().get("a")[0] = "corrupt";
        assertThat(wrapper.getParameter("a")).isEqualTo("1"); assertThat(wrapper.getParameterNames().nextElement()).isEqualTo("a");
        assertThatThrownBy(() -> wrapper.getParameterMap().put("b", new String[] {"2"})).isInstanceOf(UnsupportedOperationException.class);
    }
    @Test void unbufferedFormsRetainTheOriginalServletParameterAccess() {
        var request = body("long-body", "application/x-www-form-urlencoded"); request.addParameter("a", "original");
        var wrapper = new CachedBodyRequest(request, 2);
        assertThat(wrapper.getParameter("a")).isEqualTo("original"); assertThat(wrapper.getParameterValues("a")).containsExactly("original");
        assertThat(wrapper.getParameterMap()).containsKey("a"); assertThat(wrapper.getParameterNames().nextElement()).isEqualTo("a");
    }
    @Test void extractsWhitelistedNestedJsonFieldsWithoutRescanningRawSecrets() {
        var properties = new RaspProperties(); properties.getWhitelist().setParamNames(List.of("password"));
        var request = body("{\"password\":\"<script>x</script>\",\"user\":{\"password\":\"<script>x</script>\",\"name\":\"John\"}}", "application/json");
        var context = new RequestPayloadExtractor(properties).extract(new CachedBodyRequest(request, 1024));
        assertThat(context.rawBody()).isNull(); assertThat(context.bodyAsMap().toString()).doesNotContain("script", "password").contains("John");
        assertThat(new XssDetector().detect(context).detected()).isFalse();
    }
    @Test void extractsArrayJsonAndTextAndMalformedJson() {
        var extractor = new RequestPayloadExtractor(new RaspProperties());
        var array = extractor.extract(new CachedBodyRequest(body("[\"John\",2]", "application/problem+json"), 100));
        assertThat(array.bodyAsMap()).containsKey("$");
        var text = extractor.extract(new CachedBodyRequest(body("hello", "text/plain"), 100)); assertThat(text.rawBody()).isEqualTo("hello");
        var malformed = extractor.extract(new CachedBodyRequest(body("{broken", "application/json"), 100)); assertThat(malformed.rawBody()).isEqualTo("{broken");
    }
    @Test void formExtractionPreservesAllValuesAndExcludesOnlyConfiguredScanParameters() {
        var p = new RaspProperties(); p.getWhitelist().setParamNames(List.of("password"));
        var request = body("name=John&password=%3Cscript%3E", "application/x-www-form-urlencoded"); request.setQueryString("q=a&q=b");
        var wrapped = new CachedBodyRequest(request, 1000);
        var context = new RequestPayloadExtractor(p).extract(wrapped);
        assertThat(context.params()).containsKey("body:name").doesNotContainKey("body:password");
        assertThat(wrapped.getParameter("password")).isEqualTo("<script>");
        assertThat(wrapped.getParameterValues("q")).containsExactly("a", "b");
        assertThat(RequestPayloadExtractor.parseForm("&flag&a=&a=x+y").get("a")).containsExactly("", "x y");
        assertThat(RequestPayloadExtractor.parseForm(null)).isEmpty();
        assertThatThrownBy(() -> RequestPayloadExtractor.parseForm("bad=%GG")).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void togglesSurfacesAndPreservesContentTypeForXxe() {
        var p = new RaspProperties(); p.getScan().setHeaders(false); p.getScan().setQueryParams(false); p.getScan().setUri(false);
        var request = body("<safe/>", "application/xml"); request.addHeader("X-Custom", "value"); request.setQueryString("q=John");
        var extractor = new RequestPayloadExtractor(p);
        var context = extractor.extract(new CachedBodyRequest(request, 100));
        assertThat(context.headers()).containsOnlyKeys("Content-Type"); assertThat(context.params()).isEmpty(); assertThat(context.uri()).isEmpty();
        assertThat(extractor.scanBody(request)).isTrue();
        p.getScan().setBody(false); assertThat(extractor.scanBody(request)).isFalse();
        p.getScan().setBody(true); request.setContentType("application/octet-stream"); assertThat(extractor.scanBody(request)).isFalse();
        request.setMethod("GET"); request.setContent(new byte[0]); request.setContentType("text/plain"); assertThat(extractor.scanBody(request)).isFalse();
        request.addHeader("Transfer-Encoding", "chunked"); assertThat(extractor.scanBody(request)).isTrue();
    }
    @Test void stripsHeaderControlsAndHonorsHeaderAndParameterWhitelist() {
        var p = new RaspProperties(); p.getWhitelist().setParamNames(List.of("password"));
        var request = new MockHttpServletRequest("GET", "/api"); request.setQueryString("password=secret&q=John");
        request.addHeader("AUTHORIZATION", "Bearer secret"); request.addHeader("X-Custom", "a\rb\nc\td\u0000e");
        var context = new RequestPayloadExtractor(p).extract(request);
        assertThat(context.headers()).doesNotContainKey("AUTHORIZATION"); assertThat(context.headers().get("X-Custom")).containsExactly("abcde");
        assertThat(context.params()).containsOnlyKeys("q");
        assertThat(RequestPayloadExtractor.stripControls(null)).isEmpty();
    }
    @Test void filterExtractionErrorsDoNotSwallowApplicationFailures() throws Exception {
        var p = new RaspProperties(); p.getScan().setMaxBodySize(DataSize.ofBytes(100));
        var filter = filter(p);
        assertThatThrownBy(() -> filter.doFilter(new MockHttpServletRequest("GET", "/api"), new MockHttpServletResponse(),
                (request, response) -> { throw new IllegalStateException("application failure"); }))
                .isInstanceOf(IllegalStateException.class).hasMessage("application failure");
    }
    @Test void inputReadFailurePreservesAlreadyReadPrefixForFailOpen() throws Exception {
        var request = new FailingReadRequest();
        var p = new RaspProperties();
        var response = new MockHttpServletResponse();
        filter(p).doFilter(request, response, (incoming, outgoing) -> outgoing.getOutputStream().write(incoming.getInputStream().readAllBytes()));
        assertThat(response.getContentAsString()).isEqualTo("abcdef");
        p.setFailOpen(false);
        var blocked = new MockHttpServletResponse(); filter(p).doFilter(new FailingReadRequest(), blocked, (incoming, outgoing) -> { throw new AssertionError("blocked"); });
        assertThat(blocked.getStatus()).isEqualTo(403);
    }
    private static RaspFilter filter(RaspProperties p) {
        var engine = new RaspEngine(List.of(new XssDetector()), p.getMode(), p.isFailOpen(), p.getBlockThreshold());
        var inspection = new RaspInspectionService(engine, p, event -> {}, new DefaultListableBeanFactory().getBeanProvider(RaspMetricsBinder.class));
        return new RaspFilter(p, inspection);
    }
    private static MockHttpServletRequest body(String text, String contentType) {
        var request = new MockHttpServletRequest("POST", "/api"); request.setContentType(contentType); request.setCharacterEncoding("UTF-8");
        request.setContent(text.getBytes(StandardCharsets.UTF_8)); return request;
    }
    private static class UnknownLengthRequest extends MockHttpServletRequest {
        @Override public long getContentLengthLong() { return -1; }
    }
    private static class FailingReadRequest extends MockHttpServletRequest {
        FailingReadRequest() { super("POST", "/api"); setContentType("text/plain"); }
        private final ServletInputStream input = new ServletInputStream() {
            private int position;
            private boolean failed;
            @Override public int read() throws IOException {
                if (position == 3 && !failed) { failed = true; throw new IOException("transient read failure"); }
                return position < 6 ? "abcdef".charAt(position++) : -1;
            }
            @Override public int read(byte[] bytes, int offset, int length) throws IOException {
                int value = read(); if (value < 0) return -1; bytes[offset] = (byte) value; return 1;
            }
            @Override public boolean isFinished() { return position >= 6; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener listener) { }
        };
        @Override public ServletInputStream getInputStream() { return input; }
        @Override public long getContentLengthLong() { return -1; }
    }
}
