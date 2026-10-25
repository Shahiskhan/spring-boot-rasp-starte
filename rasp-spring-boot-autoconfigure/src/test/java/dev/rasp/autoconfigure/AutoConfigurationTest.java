package dev.rasp.autoconfigure;

import dev.rasp.core.DetectionResult;
import dev.rasp.core.RaspMode;
import dev.rasp.core.ScanContext;
import dev.rasp.core.ThreatDetector;
import dev.rasp.core.ThreatType;
import dev.rasp.core.extract.Payload;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.unit.DataSize;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AutoConfigurationTest {
    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AopAutoConfiguration.class, RaspAutoConfiguration.class));

    @Test void registersEverythingForServletApplications() {
        runner.withBean(SimpleMeterRegistry.class, SimpleMeterRegistry::new).run(context -> {
            assertThat(context).hasSingleBean(RaspFilter.class).hasSingleBean(RaspAspect.class)
                    .hasSingleBean(RaspMetricsBinder.class).hasSingleBean(RaspHealthIndicator.class)
                    .hasSingleBean(RaspRequestBodyAdvice.class).hasSingleBean(RaspResponseBodyAdvice.class);
            assertThat(context.getBeansOfType(ThreatDetector.class)).hasSize(8);
            assertThat(context.getBean(RaspProperties.class).getMode()).isEqualTo(RaspMode.BLOCK);
            assertThat(context.getBean(RaspHealthIndicator.class).health().getDetails().get("detectors")).isEqualTo(8);
        });
    }
    @Test void disabledAndNonServletContextsHaveNoProtectionBeans() {
        runner.withPropertyValues("rasp.enabled=false").run(context -> assertThat(context).doesNotHaveBean(RaspFilter.class));
        new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(RaspAutoConfiguration.class))
                .run(context -> assertThat(context).doesNotHaveBean(RaspFilter.class));
    }
    @Test void optionalMetricsAndActuatorMayBeAbsent() {
        runner.withClassLoader(new FilteredClassLoader("io.micrometer", "org.springframework.boot.actuate"))
                .run(context -> {
                    assertThat(context).hasSingleBean(RaspFilter.class).doesNotHaveBean("raspMetricsBinder").doesNotHaveBean("raspHealthIndicator");
                    assertThat(execute(context.getBean(RaspFilter.class), "q=%27+OR+1%3D1--", "127.0.0.1", "/api").getStatus()).isEqualTo(403);
                });
    }
    @Test void metricsCanBeDisabled() {
        runner.withBean(SimpleMeterRegistry.class, SimpleMeterRegistry::new).withPropertyValues("rasp.metrics.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(RaspMetricsBinder.class));
    }
    @Test void anEmptyHeaderWhitelistEnablesScanningPreviouslyExemptHeaders() {
        runner.withPropertyValues("rasp.whitelist.headers=").run(context -> {
            assertThat(context.getBean(RaspProperties.class).getWhitelist().getHeaders()).isEmpty();
            var request = new MockHttpServletRequest("GET", "/api"); request.addHeader("Cookie", "<script>x</script>");
            var response = new MockHttpServletResponse();
            context.getBean(RaspFilter.class).doFilter(request, response, (incoming, outgoing) -> outgoing.getWriter().write("OK"));
            assertThat(response.getStatus()).isEqualTo(403);
        });
    }
    @Test void monitorModeReportsButAllows() {
        var events = new ArrayList<ThreatDetectedEvent>();
        runner.withPropertyValues("rasp.mode=MONITOR").withInitializer(context -> context.addApplicationListener(event -> {
            if (event instanceof ThreatDetectedEvent threat) events.add(threat);
        })).run(context -> {
            var response = execute(context.getBean(RaspFilter.class), "q=%27+OR+1%3D1--", "127.0.0.1", "/api/search");
            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(events).isNotEmpty();
            assertThat(events.get(0).getDetection().evidence()).isEqualTo("[REDACTED]");
            assertThat(events.get(0).getTraceId()).isNotBlank();
            assertThat(events.get(0).getDetection().location()).doesNotContain("q=");
        });
    }
    @Test void strictModeTemporarilyBlocksOnlyTheActualRemoteIp() {
        runner.withPropertyValues("rasp.mode=STRICT", "rasp.rate-limit.violation-threshold=2").run(context -> {
            RaspFilter filter = context.getBean(RaspFilter.class);
            assertThat(execute(filter, "q=%27+OR+1%3D1--", "192.0.2.1", "/api").getStatus()).isEqualTo(403);
            assertThat(execute(filter, "q=%27+OR+1%3D1--", "192.0.2.1", "/api").getStatus()).isEqualTo(403);
            var blocked = execute(filter, "q=John", "192.0.2.1", "/api");
            assertThat(blocked.getStatus()).isEqualTo(403);
            assertThat(blocked.getContentAsString()).contains("RATE_LIMIT");
            assertThat(execute(filter, "q=John", "192.0.2.2", "/api").getStatus()).isEqualTo(200);
        });
    }
    @Test void pathAndIpExemptionsAreExplicitAndCanonical() {
        runner.withPropertyValues("rasp.whitelist.ips[0]=192.0.2.3").run(context -> {
            RaspFilter filter = context.getBean(RaspFilter.class);
            assertThat(execute(filter, "q=%27+OR+1%3D1--", "192.0.2.3", "/api").getStatus()).isEqualTo(200);
            assertThat(execute(filter, "q=%27+OR+1%3D1--", "127.0.0.1", "/actuator/health").getStatus()).isEqualTo(200);
            for (String path : List.of("/actuator/../api", "/actuator/%2e%2e/api", "/actuator//api", "/actuator/;x/api", "/actuator/\\../api")) {
                assertThat(execute(filter, "q=%27+OR+1%3D1--", "127.0.0.1", path).getStatus()).as(path).isEqualTo(403);
            }
        });
    }
    @Test void namedDetectorOverrideAndDisablingAreHonored() {
        runner.withUserConfiguration(CustomDetector.class).withPropertyValues("rasp.response.include-details=true", "rasp.response.http-status=422")
                .run(context -> {
                    assertThat(context.getBeansOfType(ThreatDetector.class)).hasSize(8);
                    var response = execute(context.getBean(RaspFilter.class), "q=benign", "127.0.0.1", "/api");
                    assertThat(response.getStatus()).isEqualTo(422);
                    assertThat(response.getContentAsString()).contains("SQLI", "\"score\":99").doesNotContain("secret-evidence");
                });
        runner.withUserConfiguration(CustomDetector.class).withPropertyValues("rasp.detectors.sqli.enabled=false").run(context -> {
            assertThat(execute(context.getBean(RaspFilter.class), "q=benign", "127.0.0.1", "/api").getStatus()).isEqualTo(200);
        });
    }
    @Test void configuredDetectorWrappersRetainPreparedPayloadOptimization() {
        runner.withUserConfiguration(PreparedDetector.class).run(context -> {
            assertThat(execute(context.getBean(RaspFilter.class), "q=%3CSCRIPT%3Ex%3C%2FSCRIPT%3E", "127.0.0.1", "/api").getStatus()).isEqualTo(403);
        });
    }
    @Test void detectorErrorsRespectFailOpenAndFailClosed() {
        runner.withUserConfiguration(FailingDetector.class).run(context -> {
            assertThat(execute(context.getBean(RaspFilter.class), "q=benign", "127.0.0.1", "/api").getStatus()).isEqualTo(200);
        });
        runner.withUserConfiguration(FailingDetector.class).withPropertyValues("rasp.fail-open=false").run(context -> {
            var response = execute(context.getBean(RaspFilter.class), "q=benign", "127.0.0.1", "/api");
            assertThat(response.getStatus()).isEqualTo(403);
            assertThat(response.getContentAsString()).contains("ENGINE_ERROR").doesNotContain("sensitive exception");
        });
    }
    @Test void malformedQueryRespectsFailurePolicy() {
        runner.run(context -> assertThat(execute(context.getBean(RaspFilter.class), "q=%GG", "127.0.0.1", "/api").getStatus()).isEqualTo(200));
        runner.withPropertyValues("rasp.fail-open=false").run(context -> assertThat(execute(context.getBean(RaspFilter.class), "q=%GG", "127.0.0.1", "/api").getStatus()).isEqualTo(403));
    }
    @Test void eventsCannotChangeEnforcementOrLeakRawEvidence() {
        runner.withInitializer(context -> context.addApplicationListener(event -> {
            if (event instanceof ThreatDetectedEvent) throw new IllegalStateException("subscriber failure");
        })).run(context -> assertThat(execute(context.getBean(RaspFilter.class), "q=%27+OR+1%3D1--", "127.0.0.1", "/api").getStatus()).isEqualTo(403));
    }
    @Test void validationRejectsInvalidConfiguration() {
        for (String invalid : List.of("rasp.block-threshold=101", "rasp.response.http-status=200", "rasp.cache.pattern-cache-size=0", "rasp.scan.max-body-size=0B", "rasp.scan.max-body-size=17MB", "rasp.detectors.unknown.enabled=true")) {
            runner.withPropertyValues(invalid).run(context -> assertThat(context).as(invalid).hasFailed());
        }
    }
    @Test void extractionPropertiesBindAllSupportedValues() {
        runner.withPropertyValues("rasp.scan.headers=false", "rasp.scan.query-params=false", "rasp.scan.body=false", "rasp.scan.uri=false", "rasp.scan.method-args=false",
                "rasp.scan.max-body-size=4KB", "rasp.scan.max-object-depth=4", "rasp.scan.max-object-values=32", "rasp.scan.skip-content-types[0]=text/plain",
                "rasp.whitelist.paths[0]=/public/**", "rasp.whitelist.param-names[0]=password", "rasp.whitelist.headers[0]=X-Custom",
                "rasp.cache.pattern-cache-size=64", "rasp.cache.pattern-cache-ttl-seconds=60", "rasp.detectors.xss.priority=20",
                "rasp.rate-limit.max-entries=128", "rasp.rate-limit.window-seconds=2", "rasp.rate-limit.block-seconds=2").run(context -> {
            RaspProperties p = context.getBean(RaspProperties.class);
            assertThat(p.isEnabled()).isTrue();
            assertThat(p.getScan().isHeaders()).isFalse(); assertThat(p.getScan().isQueryParams()).isFalse();
            assertThat(p.getScan().isBody()).isFalse(); assertThat(p.getScan().isUri()).isFalse(); assertThat(p.getScan().isMethodArgs()).isFalse();
            assertThat(p.getScan().getMaxBodySize()).isEqualTo(DataSize.ofKilobytes(4));
            assertThat(p.getScan().getMaxObjectDepth()).isEqualTo(4); assertThat(p.getScan().getMaxObjectValues()).isEqualTo(32);
            assertThat(p.getScan().getSkipContentTypes()).containsExactly("text/plain");
            assertThat(p.getWhitelist().getParamNames()).containsExactly("password"); assertThat(p.getWhitelist().getHeaders()).containsExactly("X-Custom");
            assertThat(p.getCache().getPatternCacheSize()).isEqualTo(64); assertThat(p.getCache().getPatternCacheTtlSeconds()).isEqualTo(60);
            assertThat(p.getDetectors().get("xss").getPriority()).isEqualTo(20);
            assertThat(p.getRateLimit().getMaxEntries()).isEqualTo(128); assertThat(p.getRateLimit().getWindowSeconds()).isEqualTo(2);
            assertThat(p.getRateLimit().getBlockSeconds()).isEqualTo(2);
            assertThat(execute(context.getBean(RaspFilter.class), "q=%27+OR+1%3D1--", "127.0.0.1", "/api").getStatus()).isEqualTo(200);
        });
    }
    @Test void alertConfigurationRejectsInvalidEndpointsBeforeAnyNetworkCall() {
        for (String endpoint : List.of("", "file:///tmp/alert", "https://user:secret@example.test/", "https://example.test/#x")) {
            runner.withPropertyValues("rasp.alerting.enabled=true", "rasp.alerting.webhook-url=" + endpoint)
                    .run(context -> assertThat(context).hasFailed());
        }
        runner.withPropertyValues("rasp.alerting.enabled=true", "rasp.alerting.threshold=1000", "rasp.alerting.webhook-url=https://example.invalid/alert")
                .run(context -> {
                    assertThat(context).hasSingleBean(RaspAlertListener.class);
                    assertThat(context.getBean(RaspProperties.class).getAlerting().getThreshold()).isEqualTo(1000);
                    assertThat(execute(context.getBean(RaspFilter.class), "q=%27+OR+1%3D1--", "127.0.0.1", "/api").getStatus()).isEqualTo(403);
                });
    }

    private static MockHttpServletResponse execute(RaspFilter filter, String query, String ip, String uri) throws Exception {
        var request = new MockHttpServletRequest("GET", uri); request.setRemoteAddr(ip); request.setQueryString(query);
        // Spoofed forwarding headers must not affect IP tracking or exemptions.
        request.addHeader("X-Forwarded-For", "192.0.2.200");
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, (incoming, outgoing) -> outgoing.getWriter().write("OK"));
        return response;
    }
    @Configuration(proxyBeanMethods = false) static class CustomDetector {
        @Bean(name = "raspSqlInjectionDetector") ThreatDetector override() {
            return new ThreatDetector() {
                @Override public DetectionResult detect(ScanContext context) { return new DetectionResult(ThreatType.SQLI, true, 99, "secret-evidence", "param:q"); }
                @Override public ThreatType getType() { return ThreatType.SQLI; }
                @Override public int getPriority() { return 500; }
            };
        }
    }
    @Configuration(proxyBeanMethods = false) static class FailingDetector {
        @Bean(name = "raspSqlInjectionDetector") ThreatDetector override() {
            return new ThreatDetector() {
                @Override public DetectionResult detect(ScanContext context) { throw new IllegalStateException("sensitive exception"); }
                @Override public ThreatType getType() { return ThreatType.SQLI; }
                @Override public int getPriority() { return 500; }
            };
        }
    }
    @Configuration(proxyBeanMethods = false) static class PreparedDetector {
        @Bean(name = "raspSqlInjectionDetector") ThreatDetector override() {
            return new ThreatDetector() {
                @Override public DetectionResult detect(ScanContext context) { throw new AssertionError("Prepared strategy must receive normalized payloads"); }
                @Override public boolean usesPreparedPayloads() { return true; }
                @Override public DetectionResult detectPrepared(ScanContext context, List<Payload> payloads) {
                    assertThat(payloads.stream().anyMatch(payload -> payload.value().equals("<script>x</script>"))).isTrue();
                    return new DetectionResult(ThreatType.SQLI, true, 99, "redacted", "param:q");
                }
                @Override public ThreatType getType() { return ThreatType.SQLI; }
                @Override public int getPriority() { return 500; }
            };
        }
    }
}
