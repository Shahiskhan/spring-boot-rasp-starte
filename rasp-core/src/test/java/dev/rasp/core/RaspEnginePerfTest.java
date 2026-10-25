package dev.rasp.core;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/** Opt-in measurements, deliberately not a hardware-independent latency promise. */
@EnabledIfSystemProperty(named = "rasp.perf", matches = "true")
class RaspEnginePerfTest {
    @Test void writesMeasuredTypicalAndLargeInputPerformance() throws Exception {
        var engine = new RaspEngine(RaspEngineTest.detectors(), RaspMode.BLOCK, true, 50);
        var typical = RaspEngineTest.query("John Doe");
        var large = RaspEngineTest.query("a".repeat(64 * 1024));
        for (int i = 0; i < 3000; i++) engine.scan(typical);
        StringBuilder report = new StringBuilder("RASP core in-process performance measurements\n")
                .append("Java: ").append(System.getProperty("java.version")).append('\n')
                .append("Available processors: ").append(Runtime.getRuntime().availableProcessors()).append('\n')
                .append("OS/architecture: ").append(System.getProperty("os.name")).append('/').append(System.getProperty("os.arch")).append('\n')
                .append("First two scenarios use one calling thread; final scenario uses exactly four worker threads.\n")
                .append("Four workers do not imply four physical cores; no CPU affinity, CPU quota, or isolated host is configured.\n")
                .append("Excludes servlet body I/O, application work, telemetry, request queueing, and network.\n")
                .append("Samples include timer/assertion overhead; p99 is the nearest-rank percentile of per-scan wall-clock latency.\n")
                .append("Targets are 10,000 requests/second and p99 < 2 ms; this report measures this machine only.\n");
        for (var scenario : List.of(new Scenario("typical small query", typical, 10000), new Scenario("64 KiB clean text query", large, 100))) {
            long[] times = new long[scenario.count()];
            long start = System.nanoTime();
            for (int i = 0; i < times.length; i++) {
                long sample = System.nanoTime();
                assertFalse(engine.scan(scenario.context()).blocked());
                times[i] = System.nanoTime() - sample;
            }
            long elapsed = System.nanoTime() - start;
            Arrays.sort(times);
            double p99ms = times[Math.min(times.length - 1, (int) Math.ceil(times.length * .99) - 1)] / 1_000_000d;
            double throughput = times.length * 1_000_000_000d / elapsed;
            report.append(String.format(Locale.ROOT, "%s: %,d scans, p99 %.3f ms, throughput %.0f scans/s%n", scenario.name(), times.length, p99ms, throughput));
        }
        measureFourWorkers(engine, typical, report);
        Path output = Path.of("target", "rasp-performance.txt");
        Files.createDirectories(output.getParent());
        Files.writeString(output, report.toString());
        assertTrue(Files.size(output) > 100);
    }

    private void measureFourWorkers(RaspEngine engine, ScanContext context, StringBuilder report) throws Exception {
        final int workers = 4;
        final int scansPerWorker = 10000;
        var pool = Executors.newFixedThreadPool(workers);
        var ready = new CountDownLatch(workers);
        var start = new CountDownLatch(1);
        List<Future<long[]>> futures = new ArrayList<>();
        try {
            for (int worker = 0; worker < workers; worker++) {
                futures.add(pool.submit(() -> {
                    // Warm each worker before the common start barrier; exclude warmup from the measurement.
                    for (int i = 0; i < 1000; i++) engine.scan(context);
                    long[] samples = new long[scansPerWorker];
                    ready.countDown();
                    if (!start.await(30, TimeUnit.SECONDS)) throw new IllegalStateException("Performance start barrier timed out");
                    for (int i = 0; i < samples.length; i++) {
                        long sample = System.nanoTime();
                        assertFalse(engine.scan(context).blocked());
                        samples[i] = System.nanoTime() - sample;
                    }
                    return samples;
                }));
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS), "Performance workers did not reach the start barrier");
            long wallStart = System.nanoTime();
            start.countDown();
            long[] allSamples = new long[workers * scansPerWorker];
            for (int worker = 0; worker < futures.size(); worker++) {
                long[] samples = futures.get(worker).get(60, TimeUnit.SECONDS);
                System.arraycopy(samples, 0, allSamples, worker * scansPerWorker, samples.length);
            }
            long elapsed = System.nanoTime() - wallStart;
            Arrays.sort(allSamples);
            double p99ms = allSamples[(int) Math.ceil(allSamples.length * .99) - 1] / 1_000_000d;
            double throughput = allSamples.length * 1_000_000_000d / elapsed;
            report.append(String.format(Locale.ROOT,
                    "typical small query, four workers: %,d scans (%,d/worker), p99 %.3f ms, aggregate throughput %.0f scans/s%n",
                    allSamples.length, scansPerWorker, p99ms, throughput));
        } finally {
            start.countDown();
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS), "Performance workers did not terminate");
        }
    }
    private record Scenario(String name, ScanContext context, int count) { }
}
