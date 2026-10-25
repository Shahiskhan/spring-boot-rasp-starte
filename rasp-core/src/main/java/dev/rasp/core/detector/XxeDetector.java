package dev.rasp.core.detector;

import dev.rasp.core.DetectionResult;
import dev.rasp.core.PatternCache;
import dev.rasp.core.ScanContext;
import dev.rasp.core.ThreatType;
import dev.rasp.core.extract.ScanPayloads;

/** Rejects DTD/entity declarations in XML bodies without invoking an XML parser. */
public final class XxeDetector extends RegexThreatDetector {
    /** Construct with default caching. */
    public XxeDetector() { this(new PatternCache()); }
    /** Precompile rules using a shared cache. */
    public XxeDetector(PatternCache cache) {
        super(ThreatType.XXE, 90, 100, cache, "<!\\s{0,8}(?:doctype|entity)\\b", "\\b(?:system|public)\\s{1,16}['\"]");
    }
    @Override public boolean usesPreparedPayloads() { return false; }
    @Override public DetectionResult detect(ScanContext context) {
        String type = ScanPayloads.contentType(context);
        if (!type.contains("xml") || context.rawBody() == null) return DetectionResult.clean(getType());
        return match(dev.rasp.core.InputNormalizer.normalize(context.rawBody()), "body:xml");
    }
}
