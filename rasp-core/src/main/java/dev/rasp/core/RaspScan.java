package dev.rasp.core;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Opts a method or parameter into argument inspection, optionally including nested DTO fields. */
@Target({ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface RaspScan {
    /** Empty selects every installed detector. */
    ThreatType[] types() default {};
    /** Permit bounded reflective inspection of nested DTOs. */
    boolean deepScan() default false;
}
