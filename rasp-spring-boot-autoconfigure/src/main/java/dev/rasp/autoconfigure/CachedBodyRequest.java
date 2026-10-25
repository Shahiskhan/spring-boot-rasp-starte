package dev.rasp.autoconfigure;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.SequenceInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/** Bounded replay buffer. An oversized or partially read body is always replayed in full downstream. */
final class CachedBodyRequest extends HttpServletRequestWrapper {
    private byte[] body;
    private ServletInputStream original;
    private byte[] prefix;
    private IOException failure;
    private ServletInputStream stream;
    private Map<String, String[]> formParameters;
    private boolean deferredForm;

    CachedBodyRequest(HttpServletRequest request, int maxBytes) {
        super(request);
        // Calling getInputStream before the container parses a chunked form destroys servlet parameter binding.
        deferredForm = "POST".equals(request.getMethod()) && request.getContentLengthLong() < 0
                && RequestPayloadExtractor.mediaType(request.getContentType()).equals("application/x-www-form-urlencoded");
        if (deferredForm) return;
        buffer(request, maxBytes);
    }
    boolean isDeferredForm() { return deferredForm; }
    void bufferDeferredBody(int maxBytes) {
        if (!deferredForm) return;
        deferredForm = false;
        buffer((HttpServletRequest) getRequest(), maxBytes);
    }
    private void buffer(HttpServletRequest request, int maxBytes) {
        if (request.getContentLengthLong() > maxBytes) return;
        var buffer = new ByteArrayOutputStream(Math.min(maxBytes, 8192));
        try {
            original = request.getInputStream();
            byte[] chunk = new byte[Math.min(maxBytes + 1, 8192)];
            while (buffer.size() <= maxBytes) {
                int count = original.read(chunk, 0, Math.min(chunk.length, maxBytes + 1 - buffer.size()));
                if (count < 0) { body = buffer.toByteArray(); return; }
                if (count == 0) continue;
                buffer.write(chunk, 0, count);
            }
        } catch (IOException error) {
            failure = error;
        }
        prefix = buffer.toByteArray();
    }

    boolean isOversized() { return body == null && failure == null; }
    IOException failure() { return failure; }
    String bodyText() { return body == null ? null : new String(body, charset()); }
    boolean isBuffered() { return body != null; }
    Charset charset() {
        String encoding = getCharacterEncoding();
        return encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
    }
    void setFormParameters(Map<String, String[]> parameters) { formParameters = parameters; }

    /** Returns input stream. */
    @Override public ServletInputStream getInputStream() throws IOException {
        if (stream != null) return stream;
        if (body != null) stream = new ReplayStream(new ByteArrayInputStream(body), null);
        else if (prefix != null && original != null) stream = new ReplayStream(new SequenceInputStream(new ByteArrayInputStream(prefix), original), original);
        else stream = super.getInputStream();
        return stream;
    }
    /** Returns reader. */
    @Override public BufferedReader getReader() throws IOException { return new BufferedReader(new InputStreamReader(getInputStream(), charset())); }
    /** Returns parameter. */
    @Override public String getParameter(String name) {
        if (formParameters == null) return super.getParameter(name);
        String[] values = formParameters.get(name);
        return values == null || values.length == 0 ? null : values[0];
    }
    /** Returns parameter map. */
    @Override public Map<String, String[]> getParameterMap() {
        if (formParameters == null) return super.getParameterMap();
        var copy = new LinkedHashMap<String, String[]>();
        formParameters.forEach((key, value) -> copy.put(key, value.clone()));
        return Collections.unmodifiableMap(copy);
    }
    /** Returns parameter values. */
    @Override public String[] getParameterValues(String name) {
        if (formParameters == null) return super.getParameterValues(name);
        String[] values = formParameters.get(name);
        return values == null ? null : values.clone();
    }
    /** Returns parameter names. */
    @Override public Enumeration<String> getParameterNames() {
        return formParameters == null ? super.getParameterNames() : Collections.enumeration(formParameters.keySet());
    }

    private static final class ReplayStream extends ServletInputStream {
        private final InputStream input;
        private final ServletInputStream delegate;
        private boolean finished;
        ReplayStream(InputStream input, ServletInputStream delegate) { this.input = input; this.delegate = delegate; }
        /** Provides the read operation for the RASP integration. */
        @Override public int read() throws IOException {
            int value = input.read();
            if (value < 0) finished = true;
            return value;
        }
        /** Provides the read operation for the RASP integration. */
        @Override public int read(byte[] bytes, int offset, int length) throws IOException {
            int count = input.read(bytes, offset, length);
            if (count < 0) finished = true;
            return count;
        }
        /** Returns finished. */
        @Override public boolean isFinished() { return finished || (delegate == null && availableQuietly() == 0); }
        /** Returns ready. */
        @Override public boolean isReady() { return delegate == null || availableQuietly() > 0 || delegate.isReady(); }
        /** Provides the close operation for the RASP integration. */
        @Override public void close() throws IOException { input.close(); }
        /** Provides the available operation for the RASP integration. */
        @Override public int available() throws IOException { return input.available(); }
        private int availableQuietly() { try { return input.available(); } catch (IOException ignored) { return 0; } }
        /** Configures read listener. */
        @Override public void setReadListener(ReadListener listener) {
            if (listener == null) throw new IllegalArgumentException("ReadListener is required");
            if (delegate != null) { delegate.setReadListener(listener); return; }
            try {
                if (!isFinished()) listener.onDataAvailable();
                if (isFinished()) listener.onAllDataRead();
            } catch (IOException error) { listener.onError(error); }
        }
    }
}
