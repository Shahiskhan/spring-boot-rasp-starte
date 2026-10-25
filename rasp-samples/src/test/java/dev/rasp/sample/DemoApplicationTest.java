package dev.rasp.sample;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class DemoApplicationTest {
    @Autowired
    private MockMvc mvc;

    @Test
    void ordinaryRequestsAndJwtAreAllowed() throws Exception {
        mvc.perform(get("/api/users").queryParam("name", "John")
                .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2huIn0.signature"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.name").value("John"));
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                .content("{\"comment\":\"A normal comment with braces {} and an apostrophe: John's.\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void sqlInjectionIsRejectedWithTraceId() throws Exception {
        mvc.perform(get("/api/search").queryParam("q", "' OR 1=1--"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("BLOCKED"))
                .andExpect(jsonPath("$.traceId").isString());
    }

    @Test
    void scriptAndExpressionPayloadsAreRejected() throws Exception {
        mvc.perform(post("/api/comment").contentType(MediaType.APPLICATION_JSON)
                .content("{\"comment\":\"<script>alert(1)</script>\"}"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/eval").queryParam("expr", "T(java.lang.Runtime).getRuntime().exec('id')"))
                .andExpect(status().isForbidden());
    }

    @Test
    void healthAndThreatCountersAreAvailable() throws Exception {
        mvc.perform(get("/api/search").queryParam("q", "' OR 1=1--"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components.rasp.status").value("UP"));
        mvc.perform(get("/actuator/metrics/rasp.threats.detected"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("rasp.threats.detected"));
    }
}
