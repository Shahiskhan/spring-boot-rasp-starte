package dev.rasp.autoconfigure;

import dev.rasp.core.RaspMode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.unit.DataSize;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Validated configuration bound from {@code rasp.*}. Defaults scan all non-exempt servlet requests. */
@Validated
@ConfigurationProperties("rasp")
public class RaspProperties {
    private boolean enabled = true;
    @NotNull private RaspMode mode = RaspMode.BLOCK;
    private boolean failOpen = true;
    @Min(1) @Max(100) private int blockThreshold = 50;
    @Valid @NotNull private Scan scan = new Scan();
    @Valid @NotNull private Whitelist whitelist = new Whitelist();
    @Valid @NotNull private Response response = new Response();
    @Valid @NotNull private Metrics metrics = new Metrics();
    @Valid @NotNull private Cache cache = new Cache();
    @Valid @NotNull private RateLimit rateLimit = new RateLimit();
    @Valid @NotNull private Alerting alerting = new Alerting();
    @Valid private Map<String, Detector> detectors = defaults();

    private static Map<String, Detector> defaults() {
        var map = new LinkedHashMap<String, Detector>();
        map.put("sqli", new Detector(100)); map.put("xss", new Detector(90));
        map.put("spel", new Detector(95)); map.put("path-traversal", new Detector(80));
        map.put("command", new Detector(85)); map.put("ldap", new Detector(70));
        map.put("nosql", new Detector(70)); map.put("xxe", new Detector(90));
        return map;
    }
    /** Returns whether RASP is enabled. */
    public boolean isEnabled() { return enabled; }
    /** Configures whether RASP is enabled. */
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    /** Returns operating mode. */
    public RaspMode getMode() { return mode; }
    /** Configures operating mode. */
    public void setMode(RaspMode mode) { this.mode = mode; }
    /** Returns whether scanning failures allow requests. */
    public boolean isFailOpen() { return failOpen; }
    /** Configures whether scanning failures allow requests. */
    public void setFailOpen(boolean failOpen) { this.failOpen = failOpen; }
    /** Returns minimum blocking risk score. */
    public int getBlockThreshold() { return blockThreshold; }
    /** Configures minimum blocking risk score. */
    public void setBlockThreshold(int blockThreshold) { this.blockThreshold = blockThreshold; }
    /** Returns request scanning settings. */
    public Scan getScan() { return scan; }
    /** Configures request scanning settings. */
    public void setScan(Scan scan) { this.scan = scan; }
    /** Returns explicit scanning bypasses. */
    public Whitelist getWhitelist() { return whitelist; }
    /** Configures explicit scanning bypasses. */
    public void setWhitelist(Whitelist whitelist) { this.whitelist = whitelist; }
    /** Returns block response settings. */
    public Response getResponse() { return response; }
    /** Configures block response settings. */
    public void setResponse(Response response) { this.response = response; }
    /** Returns metrics settings. */
    public Metrics getMetrics() { return metrics; }
    /** Configures metrics settings. */
    public void setMetrics(Metrics metrics) { this.metrics = metrics; }
    /** Returns compiled pattern cache settings. */
    public Cache getCache() { return cache; }
    /** Configures compiled pattern cache settings. */
    public void setCache(Cache cache) { this.cache = cache; }
    /** Returns STRICT mode rate limit settings. */
    public RateLimit getRateLimit() { return rateLimit; }
    /** Configures STRICT mode rate limit settings. */
    public void setRateLimit(RateLimit rateLimit) { this.rateLimit = rateLimit; }
    /** Returns asynchronous alert settings. */
    public Alerting getAlerting() { return alerting; }
    /** Configures asynchronous alert settings. */
    public void setAlerting(Alerting alerting) { this.alerting = alerting; }
    /** Returns per-family detector settings. */
    public Map<String, Detector> getDetectors() { return detectors; }
    /** Configures per-family detector settings. */
    public void setDetectors(Map<String, Detector> detectors) { this.detectors = detectors; }

    /** Request surfaces and maximum buffered body size. Oversized bodies pass through without body scanning. */
    public static class Scan {
        private boolean headers = true, queryParams = true, body = true, uri = true, methodArgs = true;
        @NotNull private DataSize maxBodySize = DataSize.ofMegabytes(1);
        @NotNull private List<String> skipContentTypes = new ArrayList<>(List.of("multipart/form-data", "application/octet-stream"));
        @Min(1) @Max(32) private int maxObjectDepth = 8;
        @Min(1) @Max(100000) private int maxObjectValues = 2048;
        /** Returns whether headers applies to this configuration. */
        public boolean isHeaders() { return headers; }
        /** Configures header scanning or bypass settings. */
        public void setHeaders(boolean headers) { this.headers = headers; }
        /** Returns whether query parameters are scanned. */
        public boolean isQueryParams() { return queryParams; }
        /** Configures whether query parameters are scanned. */
        public void setQueryParams(boolean queryParams) { this.queryParams = queryParams; }
        /** Returns whether request bodies are scanned. */
        public boolean isBody() { return body; }
        /** Configures whether request bodies are scanned. */
        public void setBody(boolean body) { this.body = body; }
        /** Returns whether request paths are scanned. */
        public boolean isUri() { return uri; }
        /** Configures whether request paths are scanned. */
        public void setUri(boolean uri) { this.uri = uri; }
        /** Returns whether annotated method arguments are scanned. */
        public boolean isMethodArgs() { return methodArgs; }
        /** Configures whether annotated method arguments are scanned. */
        public void setMethodArgs(boolean methodArgs) { this.methodArgs = methodArgs; }
        /** Returns maximum buffered request body size. */
        public DataSize getMaxBodySize() { return maxBodySize; }
        /** Configures maximum buffered request body size. */
        public void setMaxBodySize(DataSize maxBodySize) { this.maxBodySize = maxBodySize; }
        /** Returns media types excluded from body scanning. */
        public List<String> getSkipContentTypes() { return skipContentTypes; }
        /** Configures media types excluded from body scanning. */
        public void setSkipContentTypes(List<String> skipContentTypes) { this.skipContentTypes = skipContentTypes; }
        /** Returns maximum annotated object traversal depth. */
        public int getMaxObjectDepth() { return maxObjectDepth; }
        /** Configures maximum annotated object traversal depth. */
        public void setMaxObjectDepth(int maxObjectDepth) { this.maxObjectDepth = maxObjectDepth; }
        /** Returns maximum annotated object traversal values. */
        public int getMaxObjectValues() { return maxObjectValues; }
        /** Configures maximum annotated object traversal values. */
        public void setMaxObjectValues(int maxObjectValues) { this.maxObjectValues = maxObjectValues; }
    }
    /** Deliberate bypasses. Client IP is taken only from the servlet remote address. */
    public static class Whitelist {
        @NotNull private List<String> paths = new ArrayList<>(List.of("/actuator/**", "/swagger-ui/**", "/v3/api-docs/**"));
        @NotNull private List<String> ips = new ArrayList<>();
        @NotNull private List<String> paramNames = new ArrayList<>();
        @NotNull private List<String> headers = new ArrayList<>(List.of("Authorization", "Cookie", "X-CSRF", "X-CSRF-TOKEN", "Content-Length"));
        /** Returns the paths setting or collaborator. */
        public List<String> getPaths() { return paths; }
        /** Configures exempt request path patterns. */
        public void setPaths(List<String> paths) { this.paths = paths; }
        /** Returns exempt servlet remote IP addresses. */
        public List<String> getIps() { return ips; }
        /** Configures exempt servlet remote IP addresses. */
        public void setIps(List<String> ips) { this.ips = ips; }
        /** Returns exempt parameter and JSON field names. */
        public List<String> getParamNames() { return paramNames; }
        /** Configures exempt parameter and JSON field names. */
        public void setParamNames(List<String> paramNames) { this.paramNames = paramNames; }
        /** Returns header scanning or bypass settings. */
        public List<String> getHeaders() { return headers; }
        /** Configures header scanning or bypass settings. */
        public void setHeaders(List<String> headers) { this.headers = headers; }
    }
    /** Error response settings. Details are disabled to avoid disclosing detector internals. */
    public static class Response {
        private boolean includeDetails;
        @Min(400) @Max(599) private int httpStatus = 403;
        /** Returns whether include details applies to this configuration. */
        public boolean isIncludeDetails() { return includeDetails; }
        /** Configures whether responses disclose threat type and score. */
        public void setIncludeDetails(boolean includeDetails) { this.includeDetails = includeDetails; }
        /** Returns HTTP status returned for blocked operations. */
        public int getHttpStatus() { return httpStatus; }
        /** Configures HTTP status returned for blocked operations. */
        public void setHttpStatus(int httpStatus) { this.httpStatus = httpStatus; }
    }
    /** Metrics require a consumer-provided Micrometer registry. Tags have bounded cardinality. */
    public static class Metrics {
        private boolean enabled = true;
        /** Returns whether RASP is enabled. */
        public boolean isEnabled() { return enabled; }
        /** Configures whether RASP is enabled. */
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }
    /** Shared compiled-pattern cache bounds. */
    public static class Cache {
        @Min(8) @Max(100000) private int patternCacheSize = 500;
        @Min(1) @Max(86400) private long patternCacheTtlSeconds = 3600;
        /** Returns the pattern cache size setting or collaborator. */
        public int getPatternCacheSize() { return patternCacheSize; }
        /** Configures maximum compiled pattern cache entries. */
        public void setPatternCacheSize(int patternCacheSize) { this.patternCacheSize = patternCacheSize; }
        /** Returns compiled pattern cache idle lifetime in seconds. */
        public long getPatternCacheTtlSeconds() { return patternCacheTtlSeconds; }
        /** Configures compiled pattern cache idle lifetime in seconds. */
        public void setPatternCacheTtlSeconds(long patternCacheTtlSeconds) { this.patternCacheTtlSeconds = patternCacheTtlSeconds; }
    }
    /** STRICT mode bounds IP tracking and temporarily blocks repeated offenders. */
    public static class RateLimit {
        @Min(1) @Max(1000000) private int maxEntries = 10000;
        @Min(1) @Max(10000) private int violationThreshold = 3;
        @Min(1) @Max(86400) private long windowSeconds = 60;
        @Min(1) @Max(86400) private long blockSeconds = 60;
        /** Returns the max entries setting or collaborator. */
        public int getMaxEntries() { return maxEntries; }
        /** Configures maximum tracked client IP addresses. */
        public void setMaxEntries(int maxEntries) { this.maxEntries = maxEntries; }
        /** Returns violations needed for a temporary STRICT block. */
        public int getViolationThreshold() { return violationThreshold; }
        /** Configures violations needed for a temporary STRICT block. */
        public void setViolationThreshold(int violationThreshold) { this.violationThreshold = violationThreshold; }
        /** Returns STRICT violation counting window in seconds. */
        public long getWindowSeconds() { return windowSeconds; }
        /** Configures STRICT violation counting window in seconds. */
        public void setWindowSeconds(long windowSeconds) { this.windowSeconds = windowSeconds; }
        /** Returns STRICT temporary block lifetime in seconds. */
        public long getBlockSeconds() { return blockSeconds; }
        /** Configures STRICT temporary block lifetime in seconds. */
        public void setBlockSeconds(long blockSeconds) { this.blockSeconds = blockSeconds; }
    }
    /** Optional asynchronous alert endpoint. Alerts contain metadata only. */
    public static class Alerting {
        private boolean enabled;
        @Min(1) @Max(1000000) private int threshold = 10;
        private String webhookUrl = "";
        /** Returns whether RASP is enabled. */
        public boolean isEnabled() { return enabled; }
        /** Configures whether RASP is enabled. */
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        /** Returns threat events needed for an alert in one minute. */
        public int getThreshold() { return threshold; }
        /** Configures threat events needed for an alert in one minute. */
        public void setThreshold(int threshold) { this.threshold = threshold; }
        /** Returns configured HTTP or HTTPS alert destination. */
        public String getWebhookUrl() { return webhookUrl; }
        /** Configures configured HTTP or HTTPS alert destination. */
        public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }
    }
    /** Per-detector enable flag and ordering. */
    public static class Detector {
        private boolean enabled = true;
        @Min(0) @Max(1000) private int priority = 50;
        /** Provides the detector operation for the RASP integration. */
        public Detector() { }
        /** Provides the detector operation for the RASP integration. */
        public Detector(int priority) { this.priority = priority; }
        /** Returns whether RASP is enabled. */
        public boolean isEnabled() { return enabled; }
        /** Configures whether RASP is enabled. */
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        /** Returns detector evaluation priority. */
        public int getPriority() { return priority; }
        /** Configures detector evaluation priority. */
        public void setPriority(int priority) { this.priority = priority; }
    }
}
