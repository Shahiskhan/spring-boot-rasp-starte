package dev.rasp.sample;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/** Real servlet-container acceptance test, run only by {@code mvn verify -Pdocker-it}. */
@Testcontainers
class DemoContainerIT {
    @Container
    private static final GenericContainer<?> APPLICATION = new GenericContainer<>(
            DockerImageName.parse("eclipse-temurin:25-jre"))
            .withCopyFileToContainer(MountableFile.forHostPath(executableJar()), "/demo.jar")
            .withExposedPorts(8080)
            .withCommand("java", "-jar", "/demo.jar")
            .waitingFor(Wait.forHttp("/actuator/health").forStatusCode(200))
            .withStartupTimeout(Duration.ofMinutes(2));

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).build();
    private final ObjectMapper mapper = new ObjectMapper();

    private static String executableJar() {
        String configured = System.getProperty("rasp.sample.jar");
        if (configured == null || !Files.isRegularFile(Path.of(configured))) {
            throw new IllegalStateException("Packaged demo jar is missing; run mvn verify -Pdocker-it from the reactor root");
        }
        return Path.of(configured).toAbsolutePath().toString();
    }

    private URI uri(String path) {
        return URI.create("http://" + APPLICATION.getHost() + ":" + APPLICATION.getMappedPort(8080) + path);
    }

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(path)).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String encoded(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @Test
    void packagedServletApplicationPreservesBodiesAndBlocksRequiredThreats() throws Exception {
        HttpResponse<String> ordinary = client.send(HttpRequest.newBuilder(uri("/api/users?name=John"))
                        .timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2huIn0.signature").GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(ordinary.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(ordinary.body()).path("name").asText()).isEqualTo("John");

        String normalBody = "{\"comment\":\"The servlet must receive the complete JSON body.\"}";
        HttpResponse<String> replay = client.send(HttpRequest.newBuilder(uri("/api/comment"))
                        .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(normalBody)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(replay.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(replay.body())).isEqualTo(mapper.readTree(normalBody));

        HttpResponse<String> sql = get("/api/search?q=" + encoded("' OR 1=1--"));
        assertThat(sql.statusCode()).isEqualTo(403);
        assertThat(mapper.readTree(sql.body()).path("error").asText()).isEqualTo("BLOCKED");
        assertThat(mapper.readTree(sql.body()).path("traceId").asText()).isNotBlank();

        HttpResponse<String> xss = client.send(HttpRequest.newBuilder(uri("/api/comment"))
                        .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{\"comment\":\"<script>alert(1)</script>\"}")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(xss.statusCode()).isEqualTo(403);
        assertThat(get("/api/eval?expr=" + encoded("T(java.lang.Runtime).getRuntime().exec('id')")).statusCode())
                .isEqualTo(403);

        HttpResponse<String> health = get("/actuator/health");
        assertThat(health.statusCode()).isEqualTo(200);
        assertThat(mapper.readTree(health.body()).path("components").path("rasp").path("status").asText())
                .isEqualTo("UP");
        assertThat(get("/actuator/metrics/rasp.threats.detected").statusCode()).isEqualTo(200);
    }
}
