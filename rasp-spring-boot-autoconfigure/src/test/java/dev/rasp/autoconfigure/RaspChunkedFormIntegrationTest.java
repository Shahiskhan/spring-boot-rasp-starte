package dev.rasp.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = RaspFilterIntegrationTest.Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"rasp.scan.max-body-size=64B", "spring.main.banner-mode=off"})
class RaspChunkedFormIntegrationTest {
    @LocalServerPort int port;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).version(HttpClient.Version.HTTP_1_1).build();

    @Test void chunkedOversizedFormKeepsServletParameterBinding() throws Exception {
        String value = "ordinary".repeat(50);
        var response = send("/test/form", "q=hello&name=" + value);
        assertThat(response.statusCode()).isEqualTo(200);
        var json = new ObjectMapper().readTree(response.body());
        assertThat(json.path("q").get(0).asText()).isEqualTo("hello");
        assertThat(json.path("name").get(0).asText()).isEqualTo(value);
    }
    @Test void chunkedSmallFormIsScannedBeforeControllerBinding() throws Exception {
        var response = send("/test/form", "q=%3Cscript%3Ex%3C%2Fscript%3E");
        assertThat(response.statusCode()).isEqualTo(403);
    }
    @Test void chunkedOversizedRawFormRetainsEveryByte() throws Exception {
        String body = "name=" + "ordinary".repeat(50);
        var response = send("/test/text", body);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo(body);
    }
    @Test void chunkedSmallRawFormIsScannedAndReplayed() throws Exception {
        var response = send("/test/text", "name=John&age=42");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("name=John&age=42");
    }
    @Test void chunkedOversizedRawFormWithQueryKeepsOriginalBody() throws Exception {
        String body = "name=" + "ordinary".repeat(50);
        var response = send("/test/text?x=1", body);
        assertThat(response.statusCode()).isEqualTo(200); assertThat(response.body()).isEqualTo(body);
    }
    @Test void chunkedSmallRawFormWithQueryIsScannedAndReplayed() throws Exception {
        var allowed = send("/test/text?x=1", "name=John&age=42");
        assertThat(allowed.statusCode()).isEqualTo(200); assertThat(allowed.body()).isEqualTo("name=John&age=42");
        assertThat(send("/test/text?x=1", "q=%3Cscript%3Ex%3C%2Fscript%3E").statusCode()).isEqualTo(403);
    }
    @Test void manualServletReaderKeepsChunkedFormBody() throws Exception {
        for (String body : new String[] {"name=John", "name=" + "ordinary".repeat(50)}) {
            var response = send("/test/raw", body);
            assertThat(response.statusCode()).isEqualTo(200); assertThat(response.body()).isEqualTo(body);
        }
        assertThat(send("/test/raw", "q=%3Cscript%3Ex%3C%2Fscript%3E").statusCode()).isEqualTo(403);
    }
    @Test void chunkedPutAndPatchFormsAreScannedBeforeFormContentFilter() throws Exception {
        for (String method : new String[] {"PUT", "PATCH"}) {
            var allowed = send(method, "/test/form", "q=John&age=42");
            assertThat(allowed.statusCode()).isEqualTo(200);
            var json = new ObjectMapper().readTree(allowed.body());
            assertThat(json.path("q").size()).isEqualTo(1); assertThat(json.path("q").get(0).asText()).isEqualTo("John");
            assertThat(send(method, "/test/form", "q=%3Cscript%3Ex%3C%2Fscript%3E").statusCode()).isEqualTo(403);
        }
    }
    private HttpResponse<String> send(String path, String encoded) throws Exception {
        return send("POST", path, encoded);
    }
    private HttpResponse<String> send(String method, String path, String encoded) throws Exception {
        byte[] bytes = encoded.getBytes(StandardCharsets.UTF_8);
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .method(method, HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(bytes))).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
