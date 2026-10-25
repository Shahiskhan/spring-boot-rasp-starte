package dev.rasp.core;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class LargeInputRegressionTest {
    private final RaspEngine engine = new RaspEngine(RaspEngineTest.detectors(),RaspMode.BLOCK,true,50);
    @Test void largeCleanInputsRemainAllowed() {
        assertEquals(ScanResult.allowed(),engine.scan(RaspEngineTest.query("a".repeat(64*1024))));
        assertEquals(ScanResult.allowed(),engine.scan(RaspEngineTest.query("benign words ".repeat(6000))));
    }
    @ParameterizedTest @MethodSource("attackTails") void fullLargeSurfaceIncludingEncodedAttackTailIsScanned(ThreatType type,String tail) {
        String value="a".repeat(64*1024)+" "+tail;
        var context=type==ThreatType.XXE
                ? new ScanContext("POST","/xml",Map.of("Content-Type",new String[]{"application/xml"}),Map.of(),"<root>"+value+"</root>",Map.of(),null,"ip","trace")
                : RaspEngineTest.query(value);
        var result=engine.scan(context);
        assertTrue(result.blocked());
        assertFalse(result.engineError());
        assertTrue(result.detections().stream().anyMatch(d -> d.type()==type),"Expected threat family at the end of the full surface");
    }
    static Stream<Arguments> attackTails() { return Stream.of(
            Arguments.of(ThreatType.SQLI,"UNION SELECT 1"),Arguments.of(ThreatType.SQLI,"UNION%2520SELECT%25201"),
            Arguments.of(ThreatType.SQLI,"un/**/ion/**/select 1"),Arguments.of(ThreatType.XSS,"%253Cscript%253Ealert(1)"),
            Arguments.of(ThreatType.SPEL,"T(java.lang.Runtime).getRuntime()"),Arguments.of(ThreatType.PATH_TRAVERSAL,"/../../secret"),
            Arguments.of(ThreatType.PATH_TRAVERSAL,"/%252e%252e%252fsecret"),Arguments.of(ThreatType.COMMAND,"; whoami"),
            Arguments.of(ThreatType.LDAP,"*)(uid=*)"),Arguments.of(ThreatType.NOSQL,"$ne"),Arguments.of(ThreatType.XXE,"<!DOCTYPE x>")); }
}
