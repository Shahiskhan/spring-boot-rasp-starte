package dev.rasp.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Bounded canonicalization for detection only. Original application inputs are never rewritten. */
public final class InputNormalizer {
    private static final Pattern ENTITY = Pattern.compile("&(#x[0-9a-f]{1,8}|#[0-9]{1,10}|lt|gt|amp|quot|apos|colon|sol);?", Pattern.CASE_INSENSITIVE);
    private static final Pattern UNICODE = Pattern.compile("\\\\u([0-9a-f]{4})", Pattern.CASE_INSENSITIVE);
    private InputNormalizer() { }

    /** Decode two URL/entity/Java-Unicode layers, remove null/control separators, and fold case. */
    public static String normalize(String value) {
        if (value == null || value.isEmpty()) return "";
        String normalized = value;
        for (int i = 0; i < 2; i++) normalized = decodeUnicode(decodeEntities(decodePercent(normalized)));
        StringBuilder result = null;
        for (int i = 0; i < normalized.length(); i++) {
            char ch = normalized.charAt(i);
            boolean omit = ch < 32 && ch != 9 && ch != 10 && ch != 13 || ch == 127 || ch == 0x200b || ch == 0xfeff;
            if (omit && result == null) result = new StringBuilder(normalized.length()).append(normalized, 0, i);
            else if (!omit && result != null) result.append(ch);
        }
        return (result == null ? normalized : result.toString()).toLowerCase(Locale.ROOT);
    }

    private static String decodePercent(String input) {
        if (input.indexOf('%') < 0) return input;
        // Recognize historically accepted overlong encodings of path separators without accepting them as UTF-8.
        String inputLower = input.toLowerCase(Locale.ROOT);
        if (inputLower.contains("%c0%") || inputLower.contains("%c1%") || inputLower.contains("%e0%80%")) {
            input = inputLower.replace("%c0%ae", ".").replace("%c0%af", "/").replace("%c1%9c", "\\")
                    .replace("%e0%80%ae", ".").replace("%e0%80%af", "/").replace("%c0%80", "");
        }
        StringBuilder result = new StringBuilder(input.length());
        for (int i = 0; i < input.length();) {
            if (input.charAt(i) == '%' && i + 2 < input.length() && digit(input.charAt(i + 1)) >= 0 && digit(input.charAt(i + 2)) >= 0) {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                while (i + 2 < input.length() && input.charAt(i) == '%' && digit(input.charAt(i + 1)) >= 0 && digit(input.charAt(i + 2)) >= 0) {
                    bytes.write((digit(input.charAt(i + 1)) << 4) | digit(input.charAt(i + 2)));
                    i += 3;
                }
                result.append(bytes.toString(StandardCharsets.UTF_8));
            } else result.append(input.charAt(i++));
        }
        return result.toString();
    }

    private static int digit(char ch) { return Character.digit(ch, 16); }

    private static String decodeEntities(String input) {
        if (input.indexOf('&') < 0) return input;
        Matcher matcher = ENTITY.matcher(input);
        StringBuilder result = new StringBuilder(input.length());
        while (matcher.find()) {
            String entity = matcher.group(1).toLowerCase(Locale.ROOT);
            String decoded;
            if (entity.startsWith("#")) {
                try {
                    long code = Long.parseLong(entity.substring(entity.startsWith("#x") ? 2 : 1), entity.startsWith("#x") ? 16 : 10);
                    decoded = Character.isValidCodePoint((int) code) && code <= Character.MAX_CODE_POINT
                            ? new String(Character.toChars((int) code)) : matcher.group();
                } catch (IllegalArgumentException ex) { decoded = matcher.group(); }
            } else decoded = switch (entity) {
                case "lt" -> "<"; case "gt" -> ">"; case "amp" -> "&"; case "quot" -> "\"";
                case "apos" -> "'"; case "colon" -> ":"; case "sol" -> "/"; default -> matcher.group();
            };
            matcher.appendReplacement(result, Matcher.quoteReplacement(decoded));
        }
        matcher.appendTail(result);
        return result.toString();
    }

    private static String decodeUnicode(String input) {
        if (input.indexOf('\\') < 0) return input;
        Matcher matcher = UNICODE.matcher(input);
        StringBuilder result = new StringBuilder(input.length());
        while (matcher.find()) matcher.appendReplacement(result, Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(matcher.group(1), 16))));
        matcher.appendTail(result);
        return result.toString();
    }
}
