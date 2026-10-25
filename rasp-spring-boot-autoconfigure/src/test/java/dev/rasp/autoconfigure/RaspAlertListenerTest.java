package dev.rasp.autoconfigure;

import com.sun.net.httpserver.HttpServer;
import dev.rasp.core.Decision;
import dev.rasp.core.DetectionResult;
import dev.rasp.core.ThreatType;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class RaspAlertListenerTest {
    @Test void thresholdEmitsAtMostOneBoundedMetadataOnlyAlertPerMinute() throws Exception {
        var received = new CountDownLatch(1); var requests = new AtomicInteger(); var body = new AtomicReference<String>();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/alerts", exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)); requests.incrementAndGet();
            exchange.sendResponseHeaders(202, -1); exchange.close(); received.countDown();
        });
        server.start();
        try {
            var p = new RaspProperties(); p.getAlerting().setThreshold(2);
            p.getAlerting().setWebhookUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/alerts");
            try (var listener = new RaspAlertListener(p)) {
                var event = new ThreatDetectedEvent(this, new DetectionResult(ThreatType.SQLI, true, 90, "password-secret", "param:password-secret"), Decision.BLOCK, "test-trace");
                listener.detected(event); assertThat(requests).hasValue(0);
                listener.detected(event); listener.detected(event);
                assertThat(received.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(requests).hasValue(1);
                assertThat(body.get()).contains("RASP_THRESHOLD", "test-trace", "SQLI").doesNotContain("password-secret", "param:");
                assertThat(event.getDecision()).isEqualTo(Decision.BLOCK); assertThat(event.getDetection().location()).isEqualTo("param");
            }
        } finally { server.stop(0); }
    }
    @Test void eventLocationsAreReducedToASafeSurface() {
        var unknown = new ThreatDetectedEvent(this, new DetectionResult(ThreatType.XSS, true, 90, "raw", null), Decision.LOG, "trace");
        var plain = new ThreatDetectedEvent(this, new DetectionResult(ThreatType.XSS, true, 90, "raw", "attackercontrolled"), Decision.LOG, "trace");
        assertThat(unknown.getDetection().location()).isEqualTo("request");
        assertThat(plain.getDetection().location()).isEqualTo("request");
    }
}
