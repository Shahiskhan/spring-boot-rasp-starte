package dev.rasp.autoconfigure;

import dev.rasp.core.RaspProtect;
import dev.rasp.core.RaspBlockedException;
import dev.rasp.core.RaspScan;
import dev.rasp.core.ScanContext;
import dev.rasp.core.ThreatType;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.AbstractPointcutAdvisor;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/** A Spring AOP advisor whose pointcut matches only explicitly protected methods, types or parameters. */
public final class RaspAspect extends AbstractPointcutAdvisor {
    private final Supplier<RaspProperties> properties;
    private final Supplier<RaspInspectionService> inspection;
    private final Pointcut pointcut = new StaticMethodMatcherPointcut() {
        /** Provides the matches operation for the RASP integration. */
        @Override public boolean matches(Method method, Class<?> targetClass) {
            Method actual = AopUtils.getMostSpecificMethod(method, targetClass);
            return protectedMethod(actual, targetClass) || protectedMethod(method, method.getDeclaringClass());
        }
    };
    private final MethodInterceptor advice = this::scanAndInvoke;
    /** Constructs the rasp aspect with its required collaborators. */
    public RaspAspect(RaspProperties properties, RaspInspectionService inspection) {
        this(() -> properties, () -> inspection);
    }
    /** Defers engine creation until a protected operation is invoked, preserving normal bean post-processing. */
    public RaspAspect(ObjectProvider<RaspProperties> properties, ObjectProvider<RaspInspectionService> inspection) {
        this(properties::getObject, inspection::getObject);
    }
    private RaspAspect(Supplier<RaspProperties> properties, Supplier<RaspInspectionService> inspection) {
        this.properties = properties; this.inspection = inspection;
    }
    /** Returns pointcut. */
    @Override public Pointcut getPointcut() { return pointcut; }
    /** Returns advice. */
    @Override public MethodInterceptor getAdvice() { return advice; }
    /** Returns order. */
    @Override public int getOrder() { return Ordered.HIGHEST_PRECEDENCE + 50; }
    private static boolean protectedMethod(Method method, Class<?> type) {
        return AnnotatedElementUtils.hasAnnotation(type, RaspProtect.class)
                || AnnotatedElementUtils.hasAnnotation(method, RaspProtect.class)
                || AnnotatedElementUtils.hasAnnotation(method, RaspScan.class)
                || Arrays.stream(method.getParameters()).anyMatch(parameter -> parameter.isAnnotationPresent(RaspScan.class));
    }
    private Object scanAndInvoke(MethodInvocation invocation) throws Throwable {
        RaspProperties properties = this.properties.get();
        if (!properties.getScan().isMethodArgs()) return invocation.proceed();
        RaspInspectionService inspection = this.inspection.get();
        var scanner = new MethodArgumentScanner(properties);
        Class<?> type = invocation.getThis() == null ? invocation.getMethod().getDeclaringClass() : invocation.getThis().getClass();
        Method method = AopUtils.getMostSpecificMethod(invocation.getMethod(), type);
        RaspScan methodScan = AnnotatedElementUtils.findMergedAnnotation(method, RaspScan.class);
        if (methodScan == null) methodScan = AnnotatedElementUtils.findMergedAnnotation(invocation.getMethod(), RaspScan.class);
        boolean scanAll = methodScan != null || AnnotatedElementUtils.hasAnnotation(method, RaspProtect.class)
                || AnnotatedElementUtils.hasAnnotation(type, RaspProtect.class)
                || AnnotatedElementUtils.hasAnnotation(invocation.getMethod(), RaspProtect.class)
                || AnnotatedElementUtils.hasAnnotation(invocation.getMethod().getDeclaringClass(), RaspProtect.class);
        HttpServletRequest request = currentRequest();
        if (request != null && RaspRequestState.of(request).exempt) return invocation.proceed();
        Parameter[] parameters = method.getParameters();
        Parameter[] declared = invocation.getMethod().getParameters();
        for (int index = 0; index < parameters.length; index++) {
            RaspScan annotation = parameters[index].getAnnotation(RaspScan.class);
            if (annotation == null) annotation = declared[index].getAnnotation(RaspScan.class);
            if (!scanAll && annotation == null) continue;
            if (properties.getWhitelist().getParamNames().contains(parameters[index].getName())) continue;
            RaspScan selected = annotation == null ? methodScan : annotation;
            boolean deep = selected != null && selected.deepScan();
            Set<ThreatType> threats = selected == null ? Set.of() : Set.copyOf(Arrays.asList(selected.types()));
            String trace = request == null ? UUID.randomUUID().toString() : RaspRequestState.of(request).traceId;
            try {
                Map<String, String[]> values = scanner.extract("arg:" + parameters[index].getName(), invocation.getArguments()[index], deep);
                ScanContext context = new ScanContext(request == null ? "METHOD" : request.getMethod(), "", Map.of(), values,
                        null, Map.of(), new Object[0], request == null ? "" : request.getRemoteAddr(), trace);
                inspection.inspect(context, request, threats);
            } catch (RaspBlockedException blocked) { throw blocked; }
            catch (RuntimeException extractionError) { inspection.extractionFailure(trace); }
        }
        return invocation.proceed();
    }
    private static HttpServletRequest currentRequest() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes ? attributes.getRequest() : null;
    }
}
