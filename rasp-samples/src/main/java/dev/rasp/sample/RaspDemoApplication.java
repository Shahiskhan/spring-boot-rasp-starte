package dev.rasp.sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Starts the safe demonstration application. */
@SpringBootApplication
public class RaspDemoApplication {

    /**
     * Starts Spring Boot with command-line configuration.
     *
     * @param args Spring Boot command-line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(RaspDemoApplication.class, args);
    }
}
