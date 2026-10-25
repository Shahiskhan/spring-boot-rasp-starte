package dev.rasp.autoconfigure;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/** Bounded, cycle-aware traversal; bean fields are inspected only when explicitly requested. */
final class MethodArgumentScanner {
    private final RaspProperties properties;
    MethodArgumentScanner(RaspProperties properties) { this.properties = properties; }
    Map<String, String[]> extract(String name, Object value, boolean deep) {
        var result = new LinkedHashMap<String, String[]>();
        visit(name, value, deep, 0, new IdentityHashMap<>(), result);
        return result;
    }
    private void visit(String path, Object value, boolean deep, int depth, IdentityHashMap<Object, Boolean> seen, Map<String, String[]> output) {
        if (value == null) return;
        if (output.size() >= properties.getScan().getMaxObjectValues() || depth > properties.getScan().getMaxObjectDepth()) {
            throw new IllegalArgumentException("Annotated argument exceeds configured scan bounds");
        }
        if (value instanceof CharSequence || value instanceof Character || value instanceof Number || value instanceof Boolean || value instanceof Enum<?>) {
            output.put(path, new String[] {value.toString()});
            return;
        }
        if (seen.put(value, Boolean.TRUE) != null) return;
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (output.size() >= properties.getScan().getMaxObjectValues()) throw new IllegalArgumentException("Annotated argument exceeds configured scan bounds");
                String key = entry.getKey() instanceof String text ? text : "key";
                if (!properties.getWhitelist().getParamNames().contains(key)) {
                    output.put(path + ".key:" + key, new String[] {key});
                    visit(path + "." + key, entry.getValue(), deep, depth + 1, seen, output);
                }
            }
        } else if (value instanceof Iterable<?> iterable) {
            int index = 0;
            for (Object child : iterable) {
                if (index >= properties.getScan().getMaxObjectValues()) throw new IllegalArgumentException("Annotated argument exceeds configured scan bounds");
                visit(path + "[" + index++ + "]", child, deep, depth + 1, seen, output);
            }
        } else if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            if (length > properties.getScan().getMaxObjectValues()) throw new IllegalArgumentException("Annotated argument exceeds configured scan bounds");
            for (int index = 0; index < length; index++) visit(path + "[" + index + "]", Array.get(value, index), deep, depth + 1, seen, output);
        } else if (deep && !value.getClass().getName().startsWith("java.")) {
            for (Class<?> type = value.getClass(); type != null && type != Object.class; type = type.getSuperclass()) {
                for (Field field : type.getDeclaredFields()) {
                    if (field.isSynthetic() || Modifier.isStatic(field.getModifiers()) || properties.getWhitelist().getParamNames().contains(field.getName())) continue;
                    if (!field.trySetAccessible()) throw new IllegalStateException("Annotated method field could not be accessed for scanning");
                    try { visit(path + "." + field.getName(), field.get(value), true, depth + 1, seen, output); }
                    catch (IllegalAccessException inaccessible) { throw new IllegalStateException("Annotated method field could not be scanned", inaccessible); }
                }
            }
        }
    }
}
