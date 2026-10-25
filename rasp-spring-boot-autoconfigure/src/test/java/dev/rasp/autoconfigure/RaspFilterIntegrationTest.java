package dev.rasp.autoconfigure;

import dev.rasp.core.RaspBlockedException;
import dev.rasp.core.RaspProtect;
import dev.rasp.core.RaspScan;
import dev.rasp.core.ThreatType;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = RaspFilterIntegrationTest.Application.class, properties = {
        "rasp.scan.max-body-size=128B", "management.endpoints.web.exposure.include=health,metrics",
        "management.endpoint.health.show-details=always", "spring.main.banner-mode=off"})
@AutoConfigureMockMvc
class RaspFilterIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ProtectedService service;
    @Autowired MeterRegistry registry;

    @ParameterizedTest
    @ValueSource(strings = {"' OR 1=1--", "<script>alert(1)</script>", "T(java.lang.Runtime).getRuntime().exec('id')",
            "../../etc/passwd", "; whoami", "*)(|(uid=*))", "{$where: 'return true'}"})
    void blocksAttackFamiliesInQuery(String attack) throws Exception {
        mvc.perform(get("/test/search").queryParam("q", attack)).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("BLOCKED")).andExpect(jsonPath("$.threat").value("POLICY"))
                .andExpect(jsonPath("$.traceId").isString()).andExpect(header().string("Cache-Control", "no-store"));
    }
    @Test void blocksXxeOnlyForXml() throws Exception {
        String xml = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>";
        mvc.perform(post("/test/text").contentType(MediaType.APPLICATION_XML).content(xml)).andExpect(status().isForbidden());
    }
    @Test void permitsLegitimateQueryAndJwt() throws Exception {
        mvc.perform(get("/test/search").queryParam("q", "John O'Reilly")
                        .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"))
                .andExpect(status().isOk()).andExpect(content().string("John O'Reilly"))
                .andExpect(header().exists("X-RASP-Trace-Id"));
    }
    @Test void replaysJsonBodyWithoutChangingContent() throws Exception {
        mvc.perform(post("/test/json").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"John\",\"n\":42}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.name").value("John")).andExpect(jsonPath("$.n").value(42));
    }
    @Test void scansEscapedJsonValues() throws Exception {
        mvc.perform(post("/test/json").contentType(MediaType.APPLICATION_JSON).content("{\"q\":\"\\u003cscript>alert(1)</script>\"}"))
                .andExpect(status().isForbidden());
    }
    @Test void scansJsonObjectKeys() throws Exception {
        mvc.perform(post("/test/json").contentType(MediaType.APPLICATION_JSON).content("{\"$ne\":null}"))
                .andExpect(status().isForbidden());
    }
    @Test void preservesFormBindingAndRepeatedParameters() throws Exception {
        mvc.perform(post("/test/form").queryParam("q", "query").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("q=body&q=second&name=John+Smith"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.q[0]").value("query"))
                .andExpect(jsonPath("$.q[1]").value("body")).andExpect(jsonPath("$.name[0]").value("John Smith"));
    }
    @Test void blocksFormPayloadBeforeBinding() throws Exception {
        mvc.perform(post("/test/form").contentType(MediaType.APPLICATION_FORM_URLENCODED).content("q=%27+OR+1%3D1--"))
                .andExpect(status().isForbidden());
    }
    @Test void preservesKnownOversizedBody() throws Exception {
        String body = "normal ".repeat(100);
        mvc.perform(post("/test/text").contentType(MediaType.TEXT_PLAIN).content(body)).andExpect(status().isOk()).andExpect(content().string(body));
    }
    @Test void oversizeDoesNotExemptOtherSurfaces() throws Exception {
        mvc.perform(post("/test/text").contentType(MediaType.TEXT_PLAIN).content("a".repeat(300)).queryParam("q", "<script>x</script>"))
                .andExpect(status().isForbidden());
    }
    @Test void skipsBinaryBody() throws Exception {
        mvc.perform(post("/test/text").contentType(MediaType.APPLICATION_OCTET_STREAM).content("<script>x</script>"))
                .andExpect(status().isOk());
    }
    @Test void invalidJsonUsesOrdinaryMvcError() throws Exception {
        mvc.perform(post("/test/json").contentType(MediaType.APPLICATION_JSON).content("{not-json"))
                .andExpect(status().isBadRequest());
    }
    @Test void maliciousMalformedJsonIsStillScannedAsText() throws Exception {
        mvc.perform(post("/test/text").contentType(MediaType.APPLICATION_JSON).content("{broken: '<script>alert(1)</script>'"))
                .andExpect(status().isForbidden());
    }
    @Test void blocksHeadersAfterControlRemoval() throws Exception {
        mvc.perform(get("/test/search").queryParam("q", "John").header("X-Search", "<scr\tip\tt>alert(1)</script>"))
                .andExpect(status().isForbidden());
    }
    @Test void multipartFilenameIsScannedWithoutReadingFileContents() throws Exception {
        var file = new MockMultipartFile("file", "../../etc/passwd", "text/plain", "innocent".getBytes());
        mvc.perform(multipart("/test/upload").file(file)).andExpect(status().isForbidden());
    }
    @Test void legitimateMultipartFileIsAccepted() throws Exception {
        var file = new MockMultipartFile("file", "report.pdf", "application/pdf", "<script>binary</script>".getBytes());
        mvc.perform(multipart("/test/upload").file(file)).andExpect(status().isOk());
    }
    @Test void actuatorReportsHealthAndBoundedMetrics() throws Exception {
        mvc.perform(get("/test/search").queryParam("q", "' OR 1=1--")).andExpect(status().isForbidden());
        mvc.perform(get("/actuator/health")).andExpect(status().isOk()).andExpect(jsonPath("$.components.rasp.status").value("UP"));
        mvc.perform(get("/actuator/metrics/rasp.threats.detected")).andExpect(status().isOk()).andExpect(jsonPath("$.name").value("rasp.threats.detected"));
        assertThat(registry.get("rasp.threats.detected").tag("type", "SQLI").counter().count()).isGreaterThanOrEqualTo(1);
    }
    @Test void aspectProtectsScalarsAndDeepObjectsOutsideHttp() {
        assertThat(service.scalar("John")).isEqualTo("John");
        assertThatThrownBy(() -> service.scalar("' OR 1=1--")).isInstanceOf(RaspBlockedException.class);
        var node = new Node("safe"); node.child = new Node("<script>x</script>"); node.child.child = node;
        assertThatThrownBy(() -> service.deep(node)).isInstanceOf(RaspBlockedException.class);
    }
    @Test void parameterAnnotationSelectsThreatTypes() {
        assertThat(service.xssOnly("' OR 1=1--")).isEqualTo("' OR 1=1--");
        assertThatThrownBy(() -> service.xssOnly("<script>x</script>")).isInstanceOf(RaspBlockedException.class);
    }
    @Test void aspectDoesNotSwallowApplicationExceptions() {
        assertThatThrownBy(() -> service.failure("John")).isInstanceOf(IllegalStateException.class).hasMessage("application failure");
    }
    @Test void optInHtmlEncodingDoesNotAlterJson() throws Exception {
        mvc.perform(get("/test/html")).andExpect(status().isOk()).andExpect(content().string("&lt;b&gt;John&lt;/b&gt;"));
        mvc.perform(get("/test/plain")).andExpect(status().isOk()).andExpect(content().string("<b>John</b>"));
    }
    @Test void deepScanCycleTerminates() {
        var node = new Node("safe"); node.child = node;
        assertThat(service.deep(node)).isSameAs(node);
    }

    @SpringBootConfiguration @EnableAutoConfiguration @Import(Controller.class)
    static class Application {
        @Bean ProtectedService protectedService() { return new ProtectedService(); }
    }
    @RestController static class Controller {
        @GetMapping("/test/search") String search(@RequestParam String q) { return q; }
        @PostMapping("/test/json") Map<String, Object> json(@RequestBody Map<String, Object> body) { return body; }
        @PostMapping("/test/text") String text(@RequestBody String body) { return body; }
        @PostMapping("/test/raw") String raw(jakarta.servlet.http.HttpServletRequest request) throws java.io.IOException { return request.getReader().lines().collect(java.util.stream.Collectors.joining("\n")); }
        @org.springframework.web.bind.annotation.RequestMapping(value = "/test/form", method = {org.springframework.web.bind.annotation.RequestMethod.POST, org.springframework.web.bind.annotation.RequestMethod.PUT, org.springframework.web.bind.annotation.RequestMethod.PATCH})
        Map<String, ?> form(@RequestParam MultiValueMap<String, String> values) { return new LinkedHashMap<>(values); }
        @PostMapping("/test/upload") String upload(@RequestParam org.springframework.web.multipart.MultipartFile file) { return file.getOriginalFilename(); }
        @RaspEncodeHtml @GetMapping(value = "/test/html", produces = "text/html") String html() { return "<b>John</b>"; }
        @RaspEncodeHtml @GetMapping(value = "/test/plain", produces = "text/plain") String plain() { return "<b>John</b>"; }
    }
    static class ProtectedService {
        @RaspProtect public String scalar(String value) { return value; }
        @RaspScan(deepScan = true) public Node deep(Node node) { return node; }
        public String xssOnly(@RaspScan(types = ThreatType.XSS) String value) { return value; }
        @RaspProtect public void failure(String value) { throw new IllegalStateException("application failure"); }
    }
    static class Node {
        String value; Node child;
        Node(String value) { this.value = value; }
    }
}
