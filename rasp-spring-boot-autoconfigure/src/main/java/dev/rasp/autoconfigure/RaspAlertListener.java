package dev.rasp.autoconfigure;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Optional bounded asynchronous webhook delivery: at most one metadata-only alert per minute, no retries. */
public final class RaspAlertListener implements AutoCloseable {
    private static final Logger LOG = LoggerFactory.getLogger(RaspAlertListener.class);
    private final int threshold;
    private final URI endpoint;
    private final HttpClient client;
    private final ThreadPoolExecutor executor;
    private final ObjectMapper mapper = new ObjectMapper();
    private long minute = -1;
    private int count;
    private boolean alerted;
    /** Constructs the rasp alert listener with its required collaborators. */
    public RaspAlertListener(RaspProperties properties) {
        threshold = properties.getAlerting().getThreshold();
        endpoint = URI.create(properties.getAlerting().getWebhookUrl());
        if (!("https".equalsIgnoreCase(endpoint.getScheme()) || "http".equalsIgnoreCase(endpoint.getScheme()))
                || endpoint.getHost() == null || endpoint.getUserInfo() != null || endpoint.getFragment() != null) {
            throw new IllegalArgumentException("rasp.alerting.webhook-url must be an HTTP(S) URL without credentials or fragment");
        }
        executor = new ThreadPoolExecutor(1, 2, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(32), task -> {
            Thread thread = new Thread(task, "rasp-alert"); thread.setDaemon(true); return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).executor(executor).followRedirects(HttpClient.Redirect.NEVER).build();
    }
    /** Provides the detected operation for the RASP integration. */
    @EventListener public synchronized void detected(ThreatDetectedEvent event) {
        long current = System.currentTimeMillis() / 60000;
        if (minute != current) { minute = current; count = 0; alerted = false; }
        if (++count < threshold || alerted) return;
        alerted = true;
        try {
            String json = mapper.writeValueAsString(Map.of("event", "RASP_THRESHOLD", "count", count,
                    "threat", event.getDetection().type().name(), "traceId", event.getTraceId()));
            HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(3)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json)).build();
            client.sendAsync(request, HttpResponse.BodyHandlers.discarding()).whenComplete((response, failure) -> {
                if (failure != null || response.statusCode() >= 400) LOG.warn("RASP webhook delivery failed");
            });
        } catch (JsonProcessingException | RuntimeException deliveryFailure) { LOG.warn("RASP webhook dispatch failed"); }
    }
    /** Provides the close operation for the RASP integration. */
    @Override public void close() { client.shutdownNow(); executor.shutdownNow(); }
}
