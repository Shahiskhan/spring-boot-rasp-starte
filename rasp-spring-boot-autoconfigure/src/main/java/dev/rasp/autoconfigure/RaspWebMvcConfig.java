package dev.rasp.autoconfigure;

import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Registers RASP metadata interception in consumer MVC applications. */
public final class RaspWebMvcConfig implements WebMvcConfigurer {
    private final RaspHandlerInterceptor interceptor;
    /** Constructs the rasp web mvc config with its required collaborators. */
    public RaspWebMvcConfig(RaspInspectionService inspection, RaspProperties properties) { interceptor = new RaspHandlerInterceptor(inspection, properties); }
    /** Provides the add interceptors operation for the RASP integration. */
    @Override public void addInterceptors(InterceptorRegistry registry) { registry.addInterceptor(interceptor).order(Integer.MIN_VALUE); }
}
