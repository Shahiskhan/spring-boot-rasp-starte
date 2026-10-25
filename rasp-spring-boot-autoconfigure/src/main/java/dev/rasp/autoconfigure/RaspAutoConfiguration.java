package dev.rasp.autoconfigure;

import dev.rasp.core.DetectionResult;
import dev.rasp.core.PatternCache;
import dev.rasp.core.RaspEngine;
import dev.rasp.core.ScanContext;
import dev.rasp.core.ThreatDetector;
import dev.rasp.core.ThreatType;
import dev.rasp.core.extract.Payload;
import dev.rasp.core.detector.CommandInjectionDetector;
import dev.rasp.core.detector.LdapInjectionDetector;
import dev.rasp.core.detector.NoSqlInjectionDetector;
import dev.rasp.core.detector.PathTraversalDetector;
import dev.rasp.core.detector.SpelInjectionDetector;
import dev.rasp.core.detector.SqlInjectionDetector;
import dev.rasp.core.detector.XssDetector;
import dev.rasp.core.detector.XxeDetector;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Servlet;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.DispatcherServlet;

import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Zero-code servlet starter registration. Individual detector beans can be replaced by their documented bean name. */
@AutoConfiguration(afterName = {
        "org.springframework.boot.actuate.autoconfigure.metrics.MetricsAutoConfiguration",
        "org.springframework.boot.actuate.autoconfigure.metrics.CompositeMeterRegistryAutoConfiguration",
        "org.springframework.boot.actuate.autoconfigure.metrics.export.simple.SimpleMetricsExportAutoConfiguration"})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({Servlet.class, DispatcherServlet.class})
@ConditionalOnProperty(prefix = "rasp", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(RaspProperties.class)
public class RaspAutoConfiguration {
    /** Provides the rasp pattern cache operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    public PatternCache raspPatternCache(RaspProperties properties) {
        long max = properties.getScan().getMaxBodySize().toBytes();
        if (max < 1 || max > 16 * 1024 * 1024L) throw new IllegalArgumentException("rasp.scan.max-body-size must be 1 byte through 16MB");
        Set<String> allowed = Set.of("sqli", "xss", "spel", "path-traversal", "command", "ldap", "nosql", "xxe");
        if (!allowed.containsAll(properties.getDetectors().keySet())) throw new IllegalArgumentException("Unknown rasp.detectors key");
        return new PatternCache(properties.getCache().getPatternCacheSize(), Duration.ofSeconds(properties.getCache().getPatternCacheTtlSeconds()));
    }
    /** Provides the rasp sql injection detector operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean(name = "raspSqlInjectionDetector")
    public SqlInjectionDetector raspSqlInjectionDetector(PatternCache cache) { return new SqlInjectionDetector(cache); }
    /** Provides the rasp xss detector operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean(name = "raspXssDetector")
    public XssDetector raspXssDetector(PatternCache cache) { return new XssDetector(cache); }
    /** Provides the rasp spel injection detector operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean(name = "raspSpelInjectionDetector")
    public SpelInjectionDetector raspSpelInjectionDetector(PatternCache cache) { return new SpelInjectionDetector(cache); }
    /** Provides the rasp path traversal detector operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean(name = "raspPathTraversalDetector")
    public PathTraversalDetector raspPathTraversalDetector(PatternCache cache) { return new PathTraversalDetector(cache); }
    /** Provides the rasp command injection detector operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean(name = "raspCommandInjectionDetector")
    public CommandInjectionDetector raspCommandInjectionDetector(PatternCache cache) { return new CommandInjectionDetector(cache); }
    /** Provides the rasp ldap injection detector operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean(name = "raspLdapInjectionDetector")
    public LdapInjectionDetector raspLdapInjectionDetector(PatternCache cache) { return new LdapInjectionDetector(cache); }
    /** Provides the rasp no sql injection detector operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean(name = "raspNoSqlInjectionDetector")
    public NoSqlInjectionDetector raspNoSqlInjectionDetector(PatternCache cache) { return new NoSqlInjectionDetector(cache); }
    /** Provides the rasp xxe detector operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean(name = "raspXxeDetector")
    public XxeDetector raspXxeDetector(PatternCache cache) { return new XxeDetector(cache); }

    /** Provides the rasp engine operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    public RaspEngine raspEngine(List<ThreatDetector> detectors, RaspProperties properties) {
        var configured = new ArrayList<ThreatDetector>();
        for (ThreatDetector detector : detectors) {
            String key = detector.getType().name().toLowerCase(Locale.ROOT).replace('_', '-');
            RaspProperties.Detector settings = properties.getDetectors().get(key);
            if (settings == null || settings.isEnabled()) configured.add(new ConfiguredDetector(detector, settings == null ? detector.getPriority() : settings.getPriority()));
        }
        return new RaspEngine(configured, properties.getMode(), properties.isFailOpen(), properties.getBlockThreshold());
    }
    /** Provides the rasp inspection service operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    public RaspInspectionService raspInspectionService(RaspEngine engine, RaspProperties properties, ApplicationEventPublisher publisher,
                                                       ObjectProvider<RaspMetricsBinder> metrics) {
        return new RaspInspectionService(engine, properties, publisher, metrics);
    }
    /** Provides the rasp filter operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    public RaspFilter raspFilter(RaspProperties properties, RaspInspectionService inspection) { return new RaspFilter(properties, inspection); }
    /** Provides the rasp filter registration operation for the RASP integration. */
    @Bean public FilterRegistrationBean<RaspFilter> raspFilterRegistration(RaspFilter filter) {
        var registration = new FilterRegistrationBean<>(filter);
        registration.setName("raspFilter"); registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        registration.setAsyncSupported(true); registration.setDispatcherTypes(EnumSet.of(DispatcherType.REQUEST));
        return registration;
    }
    /** Provides the rasp web mvc config operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    public RaspWebMvcConfig raspWebMvcConfig(RaspInspectionService inspection, RaspProperties properties) { return new RaspWebMvcConfig(inspection, properties); }
    /** Provides the rasp aspect operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public static RaspAspect raspAspect(ObjectProvider<RaspProperties> properties, ObjectProvider<RaspInspectionService> inspection) { return new RaspAspect(properties, inspection); }
    /** Provides the rasp exception handler operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    public RaspExceptionHandler raspExceptionHandler(RaspProperties properties) { return new RaspExceptionHandler(properties); }
    /** Provides the rasp request body advice operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    public RaspRequestBodyAdvice raspRequestBodyAdvice(RaspProperties properties, RaspInspectionService inspection) { return new RaspRequestBodyAdvice(properties, inspection); }
    /** Provides the rasp response body advice operation for the RASP integration. */
    @Bean @ConditionalOnMissingBean
    public RaspResponseBodyAdvice raspResponseBodyAdvice() { return new RaspResponseBodyAdvice(); }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(MeterRegistry.class)
    static class MetricsConfiguration {
        @Bean @ConditionalOnMissingBean @ConditionalOnBean(MeterRegistry.class)
        @ConditionalOnProperty(prefix = "rasp.metrics", name = "enabled", havingValue = "true", matchIfMissing = true)
        RaspMetricsBinder raspMetricsBinder(MeterRegistry registry) { return new RaspMetricsBinder(registry); }
    }
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(HealthIndicator.class)
    static class HealthConfiguration {
        @Bean(name = "raspHealthIndicator") @ConditionalOnMissingBean(name = "raspHealthIndicator")
        RaspHealthIndicator raspHealthIndicator(RaspProperties properties, List<ThreatDetector> detectors) {
            long enabled = detectors.stream().filter(detector -> {
                String key = detector.getType().name().toLowerCase(Locale.ROOT).replace('_', '-');
                return !properties.getDetectors().containsKey(key) || properties.getDetectors().get(key).isEnabled();
            }).count();
            return new RaspHealthIndicator(properties, Math.toIntExact(enabled));
        }
    }
    /** Provides the rasp alert listener operation for the RASP integration. */
    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "rasp.alerting", name = "enabled", havingValue = "true")
    public RaspAlertListener raspAlertListener(RaspProperties properties) { return new RaspAlertListener(properties); }

    private record ConfiguredDetector(ThreatDetector delegate, int priority) implements ThreatDetector {
        /** Provides the detect operation for the RASP integration. */
        @Override public DetectionResult detect(ScanContext context) { return delegate.detect(context); }
        /** Retains the delegate's opt-in to shared request normalization. */
        @Override public boolean usesPreparedPayloads() { return delegate.usesPreparedPayloads(); }
        /** Reuses the engine's normalized payloads without repeated extraction or normalization. */
        @Override public DetectionResult detectPrepared(ScanContext context, List<Payload> payloads) { return delegate.detectPrepared(context, payloads); }
        /** Returns type. */
        @Override public ThreatType getType() { return delegate.getType(); }
        /** Returns detector evaluation priority. */
        @Override public int getPriority() { return priority; }
    }
}
