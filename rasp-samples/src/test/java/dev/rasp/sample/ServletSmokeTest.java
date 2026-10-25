package dev.rasp.sample;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/** Exercises packaged servlet behavior with real socket requests and embedded Tomcat. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ServletSmokeTest {
    @LocalServerPort
    private int port;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final ObjectMapper mapper = new ObjectMapper();

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(uri(path)).timeout(Duration.ofSeconds(10));
    }

    private HttpResponse<String> send(HttpRequest request) throws Exception {
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private HttpResponse<String> get(String path) throws Exception {
        return send(request(path).GET().build());
    }

    private HttpResponse<String> post(String path, String contentType, String body) throws Exception {
        return send(request(path).header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build());
    }

    private JsonNode json(HttpResponse<String> response) throws Exception {
        return mapper.readTree(response.body());
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @Test
    void normalQueryAndOpaqueAuthorizationHeaderWorkOverHttp() throws Exception {
        HttpResponse<String> response = send(request("/api/users?name=" + encode("John O'Neil"))
                .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2huIn0.signature").GET().build());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(json(response).path("name").asText()).isEqualTo("John O'Neil");
        assertThat(response.headers().firstValue("X-RASP-Trace-Id")).isPresent();
    }

    @Test
    void requiredQueryAndBodyThreatsAreBlockedByTheServletFilter() throws Exception {
        HttpResponse<String> sql = get("/api/search?q=" + encode("' OR 1=1--"));
        assertThat(sql.statusCode()).isEqualTo(403);
        assertThat(json(sql).path("error").asText()).isEqualTo("BLOCKED");
        assertThat(json(sql).path("traceId").asText()).isNotBlank();
        assertThat(sql.body()).doesNotContain("OR 1=1");

        assertThat(post("/api/comment", "application/json", "{\"comment\":\"<script>alert(1)</script>\"}").statusCode())
                .isEqualTo(403);
        assertThat(get("/api/eval?expr=" + encode("T(java.lang.Runtime).getRuntime().exec('id')")).statusCode())
                .isEqualTo(403);
        assertThat(post("/api/form", "application/x-www-form-urlencoded", "name=" + encode("' OR 1=1--")).statusCode())
                .isEqualTo(403);
    }

    @Test
    void jsonAndFormBodiesReachTheActualControllerIntact() throws Exception {
        String comment = "{\"comment\":\"John's ordinary JSON: braces {}, plus +, and ampersand &.\"}";
        HttpResponse<String> jsonResponse = post("/api/comment", "application/json; charset=UTF-8", comment);
        assertThat(jsonResponse.statusCode()).isEqualTo(200);
        assertThat(json(jsonResponse)).isEqualTo(mapper.readTree(comment));

        String name = "Zoë + John & family";
        HttpResponse<String> formResponse = post("/api/form", "application/x-www-form-urlencoded; charset=UTF-8", "name=" + encode(name));
        assertThat(formResponse.statusCode()).isEqualTo(200);
        assertThat(json(formResponse).path("name").asText()).isEqualTo(name);
    }

    @Test
    void realManagementEndpointsExposeHealthyRaspAndCounters() throws Exception {
        assertThat(get("/api/search?q=" + encode("' OR 1=1--")).statusCode()).isEqualTo(403);
        HttpResponse<String> health = get("/actuator/health");
        assertThat(health.statusCode()).isEqualTo(200);
        assertThat(json(health).path("components").path("rasp").path("status").asText()).isEqualTo("UP");
        HttpResponse<String> metrics = get("/actuator/metrics/rasp.threats.detected");
        assertThat(metrics.statusCode()).isEqualTo(200);
        assertThat(json(metrics).path("name").asText()).isEqualTo("rasp.threats.detected");
    }
}
