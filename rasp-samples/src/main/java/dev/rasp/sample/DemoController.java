package dev.rasp.sample;

import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Safe, inert endpoints for exercising each detector. */
@RestController
@RequestMapping("/api")
public class DemoController {
    private final DemoService service;

    /**
     * Creates the sample controller.
     *
     * @param service Spring-managed service proxy demonstrating annotated protection
     */
    public DemoController(DemoService service) {
        this.service = service;
    }

    /**
     * Echoes a search string; no database is queried.
     *
     * @param q search text
     * @return a JSON object containing the original search text
     */
    @GetMapping("/search")
    public Map<String, String> search(@RequestParam String q) {
        return Map.of("query", q);
    }

    /**
     * Echoes a display name.
     *
     * @param name display name
     * @return a JSON object containing the original name
     */
    @GetMapping("/users")
    public Map<String, String> users(@RequestParam String name) {
        return Map.of("name", name);
    }

    /**
     * Echoes a JSON comment; no HTML is rendered.
     *
     * @param comment deserialized JSON object
     * @return the submitted object as JSON
     */
    @PostMapping(value = "/comment", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> comment(@RequestBody Map<String, Object> comment) {
        return comment;
    }

    /**
     * Echoes a form field after servlet form parsing; no database is queried.
     *
     * @param name decoded form field
     * @return a JSON object containing the original field value
     */
    @PostMapping(value = "/form", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, String> form(@RequestParam String name) {
        return Map.of("name", name);
    }

    /**
     * Echoes an expression; it is never parsed or executed.
     *
     * @param expr inert expression text
     * @return a JSON object containing the original expression
     */
    @GetMapping("/eval")
    public Map<String, String> expression(@RequestParam String expr) {
        return Map.of("expression", expr);
    }

    /**
     * Echoes a filename; no filesystem access occurs.
     *
     * @param name inert filename
     * @return a JSON object containing the original filename
     */
    @GetMapping("/file")
    public Map<String, String> file(@RequestParam String name) {
        return Map.of("filename", name);
    }

    /**
     * Echoes a command candidate; no process is created.
     *
     * @param value inert command text
     * @return a JSON object containing the original command text
     */
    @GetMapping("/command")
    public Map<String, String> command(@RequestParam String value) {
        return Map.of("command", value);
    }

    /**
     * Echoes a directory search; no LDAP server is contacted.
     *
     * @param filter inert LDAP filter text
     * @return a JSON object containing the original filter
     */
    @GetMapping("/directory")
    public Map<String, String> directory(@RequestParam String filter) {
        return Map.of("filter", filter);
    }

    /**
     * Echoes a JSON query; no NoSQL database is queried.
     *
     * @param query deserialized inert query object
     * @return the submitted object as JSON
     */
    @PostMapping(value = "/query", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> query(@RequestBody Map<String, Object> query) {
        return query;
    }

    /**
     * Echoes XML as a JSON string, without invoking an XML parser.
     *
     * @param document inert XML text
     * @return a JSON object containing the original XML text
     */
    @PostMapping(value = "/xml", consumes = {MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_XML_VALUE})
    public Map<String, String> xml(@RequestBody String document) {
        return Map.of("xml", document);
    }

    /**
     * Exercises an annotated service method through its Spring proxy.
     *
     * @param value inert text passed to the service proxy
     * @return a JSON object containing the allowed service result
     * @throws dev.rasp.core.RaspBlockedException when service argument policy rejects the value
     */
    @PostMapping(value = "/service", consumes = MediaType.TEXT_PLAIN_VALUE)
    public Map<String, String> service(@RequestBody String value) {
        return Map.of("value", service.inspect(value));
    }
}
