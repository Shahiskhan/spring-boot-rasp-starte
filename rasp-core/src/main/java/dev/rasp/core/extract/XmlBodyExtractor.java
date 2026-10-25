package dev.rasp.core.extract;

import java.util.List;

/** Retains XML as text; deliberately does not instantiate an XML parser or resolve any entities. */
public final class XmlBodyExtractor implements PayloadExtractor {
    @Override public List<Payload> extract(String body) {
        return body == null || body.isEmpty() ? List.of() : List.of(new Payload("body:xml", body));
    }
}
