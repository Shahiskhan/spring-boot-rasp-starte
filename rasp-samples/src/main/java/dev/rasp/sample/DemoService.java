package dev.rasp.sample;

import dev.rasp.core.RaspProtect;
import dev.rasp.core.RaspScan;
import org.springframework.stereotype.Service;

/** Demonstrates protection at a proxied service boundary. */
@Service
public class DemoService {

    /**
     * Returns a value inspected at the Spring proxy boundary without evaluating it.
     *
     * @param value inert text to inspect
     * @return the original text when policy allows the invocation
     * @throws dev.rasp.core.RaspBlockedException when the configured policy rejects the text
     */
    @RaspProtect
    public String inspect(@RaspScan String value) {
        return value;
    }
}
