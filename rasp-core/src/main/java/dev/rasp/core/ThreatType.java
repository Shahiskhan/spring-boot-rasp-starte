package dev.rasp.core;

/** Supported families of suspicious input. Findings are heuristic, not proof of exploitation. */
public enum ThreatType { SQLI, XSS, SPEL, PATH_TRAVERSAL, COMMAND, LDAP, NOSQL, XXE }
