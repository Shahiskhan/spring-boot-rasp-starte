package dev.rasp.autoconfigure;

import dev.rasp.core.RaspBlockedException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/** Converts service/aspect/interceptor blocks into the same safe response used by the servlet filter. */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public final class RaspExceptionHandler {
    private final RaspProperties properties;
    private final RaspBlockResponse response;
    /** Constructs the rasp exception handler with its required collaborators. */
    public RaspExceptionHandler(RaspProperties properties) { this.properties = properties; response = new RaspBlockResponse(properties); }
    /** Provides the blocked operation for the RASP integration. */
    @ExceptionHandler(RaspBlockedException.class)
    public ResponseEntity<Map<String, Object>> blocked(RaspBlockedException blocked) {
        return ResponseEntity.status(properties.getResponse().getHttpStatus()).cacheControl(CacheControl.noStore()).body(response.body(blocked));
    }
}
