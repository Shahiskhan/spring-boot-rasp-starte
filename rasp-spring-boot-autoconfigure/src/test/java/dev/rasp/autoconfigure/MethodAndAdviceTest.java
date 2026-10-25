package dev.rasp.autoconfigure;

import dev.rasp.core.RaspBlockedException;
import dev.rasp.core.RaspEngine;
import dev.rasp.core.RaspMode;
import dev.rasp.core.RaspProtect;
import dev.rasp.core.RaspScan;
import dev.rasp.core.ScanContext;
import dev.rasp.core.ThreatType;
import dev.rasp.core.detector.SqlInjectionDetector;
import dev.rasp.core.detector.XssDetector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerMapping;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MethodAndAdviceTest {
    @AfterEach void clearRequest() { RequestContextHolder.resetRequestAttributes(); }

    @Test void reflectionIsOptInAndHandlesArraysCollectionsMapsAndCycles() {
        var p = new RaspProperties(); var scanner = new MethodArgumentScanner(p);
        var object = new Node("John"); object.next = object;
        assertThat(scanner.extract("a", object, false)).isEmpty();
        assertThat(scanner.extract("a", object, true).values().stream().flatMap(java.util.Arrays::stream)).contains("John");
        assertThat(scanner.extract("a", new Object[] {"a", List.of("b"), Map.of("name", "c"), 12, true, 'd', ThreatType.XSS}, false)).hasSize(8);
        assertThat(scanner.extract("a", new Object(), true)).isEmpty();
        assertThat(scanner.extract("a", null, true)).isEmpty();
        p.getWhitelist().setParamNames(List.of("value"));
        assertThat(scanner.extract("a", object, true)).isEmpty();
    }
    @Test void methodTraversalLimitsAreErrorsIncludingNullValuedMaps() {
        var p = new RaspProperties(); p.getScan().setMaxObjectValues(2);
        var scanner = new MethodArgumentScanner(p);
        var nullMap = new LinkedHashMap<String, Object>(); nullMap.put("a", null); nullMap.put("b", null); nullMap.put("c", null);
        assertThatThrownBy(() -> scanner.extract("a", nullMap, true)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> scanner.extract("a", new int[] {1, 2, 3}, false)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> scanner.extract("a", List.of("1", "2", "3"), false)).isInstanceOf(IllegalArgumentException.class);
        p.getScan().setMaxObjectDepth(1);
        var root = new Node("a"); root.next = new Node("b"); root.next.next = new Node("c");
        assertThatThrownBy(() -> scanner.extract("a", root, true)).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void aspectRespectsTypesWhitelistsAndClassProtection() {
        var p = new RaspProperties();
        var target = proxy(new ClassProtected(), p);
        assertThat(target.call("John")).isEqualTo("John");
        assertThatThrownBy(() -> target.call("' OR 1=1--")).isInstanceOf(RaspBlockedException.class);
        p.getWhitelist().setParamNames(List.of("password"));
        assertThat(target.password("<script>x</script>")).contains("script");
        p.getScan().setMethodArgs(false);
        assertThat(target.call("' OR 1=1--")).contains("OR");
    }
    @Test void interfaceMethodAndParameterAnnotationsAreRecognized() {
        var p = new RaspProperties();
        var factory = new ProxyFactory(new InterfaceImpl()); factory.addAdvisor(new RaspAspect(p, inspection(p)));
        var target = (Interface) factory.getProxy();
        assertThatThrownBy(() -> target.method("<script>x</script>")).isInstanceOf(RaspBlockedException.class);
        assertThat(target.parameter("' OR 1=1--")).contains("OR");
        assertThatThrownBy(() -> target.parameter("<script>x</script>")).isInstanceOf(RaspBlockedException.class);
    }
    @Test void aspectAppliesFailPolicyToTraversalErrorsAndPreservesRealExceptions() {
        var p = new RaspProperties(); p.getScan().setMaxObjectValues(1);
        var target = proxy(new Annotated(), p);
        assertThat(target.deep(List.of("one", "two"))).hasSize(2);
        p.setFailOpen(false);
        assertThatThrownBy(() -> target.deep(List.of("one", "two"))).isInstanceOf(RaspBlockedException.class);
        p.setMode(RaspMode.MONITOR);
        assertThat(target.deep(List.of("one", "two"))).hasSize(2);
        assertThatThrownBy(() -> target.failure("John")).isInstanceOf(UnsupportedOperationException.class).hasMessage("actual invocation");
    }
    @Test void httpExemptionAlsoBypassesMethodProtection() {
        var p = new RaspProperties(); var request = new MockHttpServletRequest("GET", "/public");
        RaspRequestState.of(request).exempt = true;
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        assertThat(proxy(new Annotated(), p).scalar("<script>x</script>")).contains("script");
    }
    @Test void requestBodyAdviceScansOnlyExplicitParametersAndHandlesFailurePolicy() throws Exception {
        var p = new RaspProperties(); var inspection = inspection(p); var advice = new RaspRequestBodyAdvice(p, inspection);
        var parameter = new MethodParameter(Annotated.class.getDeclaredMethod("body", Node.class), 0);
        var plain = new MethodParameter(Annotated.class.getDeclaredMethod("scalar", String.class), 0);
        assertThat(advice.supports(parameter, Node.class, StringHttpMessageConverter.class)).isTrue();
        assertThat(advice.supports(plain, String.class, StringHttpMessageConverter.class)).isFalse();
        var node = new Node("<script>x</script>"); var input = new MockHttpInputMessage(new byte[0]);
        assertThat(advice.afterBodyRead(node, input, parameter, Node.class, StringHttpMessageConverter.class)).isSameAs(node);
        var request = new MockHttpServletRequest("POST", "/api"); RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        assertThatThrownBy(() -> advice.afterBodyRead(node, input, parameter, Node.class, StringHttpMessageConverter.class)).isInstanceOf(RaspBlockedException.class);
        RaspRequestState.of(request).exempt = true;
        assertThat(advice.afterBodyRead(node, input, parameter, Node.class, StringHttpMessageConverter.class)).isSameAs(node);
        RaspRequestState.of(request).exempt = false; RaspRequestState.of(request).oversized = true;
        assertThat(advice.afterBodyRead(node, input, parameter, Node.class, StringHttpMessageConverter.class)).isSameAs(node);
        RaspRequestState.of(request).oversized = false;
        node.value = "safe"; node.next = new Node("safe"); p.getScan().setMaxObjectDepth(1);
        assertThat(advice.afterBodyRead(node, input, parameter, Node.class, StringHttpMessageConverter.class)).isSameAs(node);
        p.setFailOpen(false);
        assertThatThrownBy(() -> advice.afterBodyRead(node, input, parameter, Node.class, StringHttpMessageConverter.class)).isInstanceOf(RaspBlockedException.class);
        assertThat(advice.afterBodyRead("plain", input, plain, String.class, StringHttpMessageConverter.class)).isEqualTo("plain");
    }
    @Test void interceptorScansPathVariablesAndMapsExtractionFailures() {
        var p = new RaspProperties(); var interceptor = new RaspHandlerInterceptor(inspection(p), p);
        var request = new MockHttpServletRequest("GET", "/api/value");
        request.setAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE, Map.of("file", "../../etc/passwd", "name", "<script>x</script>"));
        assertThatThrownBy(() -> interceptor.preHandle(request, new MockHttpServletResponse(), new Object())).isInstanceOf(RaspBlockedException.class);
        RaspRequestState.of(request).exempt = true;
        assertThat(interceptor.preHandle(request, new MockHttpServletResponse(), new Object())).isTrue();
    }
    @Test void htmlResponseAdviceNeverEncodesAnotherOutputContextOrNull() throws Exception {
        var advice = new RaspResponseBodyAdvice();
        var method = new MethodParameter(Annotated.class.getDeclaredMethod("encoded"), -1);
        assertThat(advice.supports(method, StringHttpMessageConverter.class)).isTrue();
        assertThat(advice.beforeBodyWrite("<b>", method, MediaType.TEXT_HTML, StringHttpMessageConverter.class, null, null)).isEqualTo("&lt;b&gt;");
        assertThat(advice.beforeBodyWrite("<b>", method, MediaType.APPLICATION_JSON, StringHttpMessageConverter.class, null, null)).isEqualTo("<b>");
        assertThat(advice.beforeBodyWrite(null, method, MediaType.TEXT_HTML, StringHttpMessageConverter.class, null, null)).isNull();
    }
    @Test void aMetricsFailureCannotTurnAThreatBlockIntoFailOpen() {
        var p = new RaspProperties();
        var factory = new DefaultListableBeanFactory();
        factory.registerBeanDefinition("brokenMetrics", BeanDefinitionBuilder.genericBeanDefinition(RaspMetricsBinder.class,
                () -> { throw new IllegalStateException("registry is unavailable"); }).getBeanDefinition());
        var engine = new RaspEngine(List.of(new XssDetector()), RaspMode.BLOCK, true, 50);
        var inspection = new RaspInspectionService(engine, p, event -> {}, factory.getBeanProvider(RaspMetricsBinder.class));
        var context = new ScanContext("GET", "", Map.of(), Map.of("q", new String[] {"<script>x</script>"}), null, Map.of(), new Object[0], "127.0.0.1", "trace");
        assertThatThrownBy(() -> inspection.inspect(context, null, Set.of())).isInstanceOf(RaspBlockedException.class);
    }
    private static RaspInspectionService inspection(RaspProperties properties) {
        var engine = new RaspEngine(List.of(new XssDetector(), new SqlInjectionDetector()), properties.getMode(), properties.isFailOpen(), properties.getBlockThreshold());
        return new RaspInspectionService(engine, properties, event -> {}, new DefaultListableBeanFactory().getBeanProvider(RaspMetricsBinder.class));
    }
    @SuppressWarnings("unchecked") private static <T> T proxy(T target, RaspProperties properties) {
        var factory = new ProxyFactory(target); factory.addAdvisor(new RaspAspect(properties, inspection(properties))); return (T) factory.getProxy();
    }
    static class Node { static String ignored = "static"; String value; Node next; Node(String value) { this.value = value; } }
    @RaspProtect static class ClassProtected {
        public String call(String value) { return value; }
        public String password(String password) { return password; }
    }
    static class Annotated {
        @RaspProtect public String scalar(String value) { return value; }
        @RaspScan(deepScan = true) public List<String> deep(List<String> values) { return values; }
        public Node body(@RaspScan(deepScan = true) Node body) { return body; }
        @RaspProtect public void failure(String value) { throw new UnsupportedOperationException("actual invocation"); }
        @RaspEncodeHtml public String encoded() { return "<b>"; }
    }
    interface Interface {
        @RaspScan String method(String value);
        String parameter(@RaspScan(types = ThreatType.XSS) String value);
    }
    static class InterfaceImpl implements Interface {
        @Override public String method(String value) { return value; }
        @Override public String parameter(String value) { return value; }
    }
}
