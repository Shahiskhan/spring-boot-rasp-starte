package dev.rasp.autoconfigure;

import dev.rasp.core.RaspBlockedException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/** Early servlet interception with a bounded replay buffer and no detector network calls. */
public final class RaspFilter extends OncePerRequestFilter {
    private final RaspProperties properties;
    private final RaspInspectionService inspection;
    private final RequestPayloadExtractor extractor;
    private final RaspBlockResponse blockedResponse;
    /** Constructs the rasp filter with its required collaborators. */
    public RaspFilter(RaspProperties properties, RaspInspectionService inspection) {
        this.properties = properties; this.inspection = inspection;
        extractor = new RequestPayloadExtractor(properties);
        blockedResponse = new RaspBlockResponse(properties);
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        RaspRequestState state = RaspRequestState.of(request);
        response.setHeader("X-RASP-Trace-Id", state.traceId);
        state.exempt = inspection.exempt(request);
        if (state.exempt) { chain.doFilter(request, response); return; }
        HttpServletRequest effective = request;
        try {
            inspection.beforeRequest(request);
            try {
                if (extractor.scanBody(request)) {
                    var cached = new CachedBodyRequest(request, Math.toIntExact(properties.getScan().getMaxBodySize().toBytes()));
                    effective = cached;
                    state.oversized = cached.isOversized();
                    if (cached.failure() != null) inspection.extractionFailure(request);
                }
                inspection.inspect(extractor.extract(effective), effective, Set.of());
            } catch (RaspBlockedException blocked) { throw blocked; }
            catch (RuntimeException extractionError) { inspection.extractionFailure(request); }
        } catch (RaspBlockedException blocked) {
            blockedResponse.write(response, blocked);
            return;
        }
        // Application exceptions intentionally remain outside the extraction fail-open boundary.
        chain.doFilter(effective, response);
    }
}
