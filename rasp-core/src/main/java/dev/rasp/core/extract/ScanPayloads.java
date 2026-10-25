package dev.rasp.core.extract;

import dev.rasp.core.ScanContext;
import dev.rasp.core.InputNormalizer;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Nonreflective traversal of standard containers. DTO reflection belongs only in opted-in integrations. */
public final class ScanPayloads {
    private ScanPayloads() { }

    /** Extract once and canonicalize once per surface; returned values must not be normalized again. */
    public static List<Payload> normalizedFrom(ScanContext context) {
        return from(context).stream().map(payload -> new Payload(payload.location(), InputNormalizer.normalize(payload.value()))).toList();
    }

    /** Flatten textual request surfaces. Structures are limited to depth 32 and 8192 values. */
    public static List<Payload> from(ScanContext context) {
        List<Payload> result = new ArrayList<>();
        Budget budget = new Budget();
        if (context.uri() != null) append(result, new Payload("uri", context.uri()));
        context.headers().forEach((name, values) -> {
            budget.visit();
            if (name != null) {
                append(result, new Payload("header-name", name));
                for (String value : values) {
                    budget.visit();
                    if (value != null) append(result, new Payload("header:" + name, value));
                }
            }
        });
        context.params().forEach((name, values) -> {
            budget.visit();
            append(result, new Payload("param-name", name));
            for (String value : values) {
                budget.visit();
                if (value != null) append(result, new Payload("param:" + name, value));
            }
        });
        if (!context.bodyAsMap().isEmpty()) flatten("body:$", context.bodyAsMap(), result);
        else if (context.rawBody() != null && !context.rawBody().isEmpty()) {
            String type = contentType(context);
            if (type.contains("json")) {
                try { result.addAll(new JsonBodyExtractor().extract(context.rawBody())); }
                catch (IllegalArgumentException ex) {
                    // A String endpoint may legitimately accept malformed JSON; still inspect its raw attack syntax.
                    result.add(new Payload("body:raw", context.rawBody()));
                }
            }
            else if (type.contains("application/x-www-form-urlencoded")) result.addAll(new FormBodyExtractor().extract(context.rawBody()));
            else result.add(new Payload(type.contains("xml") ? "body:xml" : "body:raw", context.rawBody()));
        }
        Object[] arguments = context.methodArgs();
        if (arguments.length > 8192) throw new IllegalArgumentException("Too many method arguments");
        for (int i = 0; i < arguments.length; i++) flatten("arg:" + i, arguments[i], result);
        if (result.size() > 8192) throw new IllegalArgumentException("Too many scan values");
        return List.copyOf(result);
    }

    /** Find Content-Type case-insensitively without assuming a particular servlet container. */
    public static String contentType(ScanContext context) {
        return context.headers().entrySet().stream().filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase("content-type"))
                .flatMap(e -> java.util.Arrays.stream(e.getValue())).filter(java.util.Objects::nonNull).findFirst().orElse("").toLowerCase(Locale.ROOT);
    }

    /** Flatten only maps, iterables, arrays and scalar values; arbitrary object methods are never invoked. */
    public static void flatten(String path, Object value, List<Payload> result) {
        walk(path, value, result, 0, Collections.newSetFromMap(new IdentityHashMap<>()), new Budget());
    }

    private static void walk(String path, Object value, List<Payload> result, int depth, Set<Object> visited, Budget budget) {
        budget.visit();
        if (depth > 32 || result.size() >= 8192) throw new IllegalArgumentException("Scan structure exceeds configured safety bounds");
        if (value == null) return;
        if (value instanceof CharSequence || value instanceof Number || value instanceof Boolean || value instanceof Character || value instanceof Enum<?>) {
            append(result, new Payload(path, String.valueOf(value)));
            return;
        }
        if (!visited.add(value)) return;
        if (value instanceof Map<?,?> map) {
            map.forEach((key, nested) -> {
                budget.visit();
                if (key instanceof String text) {
                    append(result, new Payload(path + ".<key>", text));
                    walk(path + "." + text, nested, result, depth + 1, visited, budget);
                }
            });
        } else if (value instanceof Iterable<?> values) {
            int index = 0;
            for (Object nested : values) walk(path + "[" + index++ + "]", nested, result, depth + 1, visited, budget);
        } else if (value.getClass().isArray()) {
            for (int i = 0; i < Array.getLength(value); i++) walk(path + "[" + i + "]", Array.get(value, i), result, depth + 1, visited, budget);
        }
        visited.remove(value);
    }

    private static void append(List<Payload> result, Payload payload) {
        if (result.size() >= 8192) throw new IllegalArgumentException("Too many scan values");
        result.add(payload);
    }

    private static final class Budget {
        private int remaining = 8192;
        void visit() {
            if (--remaining < 0) throw new IllegalArgumentException("Too many traversed scan nodes");
        }
    }
}
