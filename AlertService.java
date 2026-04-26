package com.phishguard.service;

import com.phishguard.model.PhishingThreat;
import com.phishguard.model.PhishingThreat.ThreatLevel;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AlertService — pushes real-time threat alerts over WebSocket (STOMP).
 *
 * Frontend subscribes to /topic/alerts/{sessionId} and receives JSON alerts
 * the moment the detection engine flags a threat. This drives the popup/alarm
 * UI that appears immediately after login.
 */
@Service
public class AlertService {

    private final SimpMessagingTemplate messagingTemplate;

    // Per-session threat counters (in prod, back with Redis or DB)
    private final ConcurrentHashMap<String, AtomicLong> threatCounters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long>       lastAlertTime  = new ConcurrentHashMap<>();

    private static final long ALERT_COOLDOWN_MS = 3_000; // prevent spam per session

    public AlertService(SimpMessagingTemplate messagingTemplate) {
        this.messagingTemplate = messagingTemplate;
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /**
     * Called by the controller after every MEDIUM/HIGH/CRITICAL detection.
     * Sends a WebSocket alert to the user's session and broadcasts to admin dashboard.
     */
    public void sendThreatAlert(PhishingThreat threat) {
        String sessionId = threat.getSessionId();

        // Rate-limit: one alert per 3 s per session to avoid UI flooding
        long now = System.currentTimeMillis();
        Long last = lastAlertTime.get(sessionId);
        if (last != null && (now - last) < ALERT_COOLDOWN_MS
                && threat.getThreatLevel() != ThreatLevel.CRITICAL) {
            return;
        }
        lastAlertTime.put(sessionId, now);

        // Increment counter
        threatCounters.computeIfAbsent(sessionId, k -> new AtomicLong(0)).incrementAndGet();

        Map<String, Object> alertPayload = buildAlertPayload(threat);

        // Push to individual user session
        messagingTemplate.convertAndSend("/topic/alerts/" + sessionId, alertPayload);

        // Broadcast to admin monitor channel
        messagingTemplate.convertAndSend("/topic/admin/threats", alertPayload);

        System.out.printf("[Alert] SENT | session=%s | level=%s | type=%s%n",
            sessionId, threat.getThreatLevel(), threat.getThreatType());
    }

    /**
     * Sends a system-wide broadcast (e.g. a new zero-day pattern discovered).
     */
    public void broadcastSystemAlert(String message, String severity) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("type", "SYSTEM_ALERT");
        payload.put("message", message);
        payload.put("severity", severity);
        payload.put("timestamp", System.currentTimeMillis());
        messagingTemplate.convertAndSend("/topic/system", payload);
    }

    /** Returns how many threats have been detected for this session. */
    public long getThreatCount(String sessionId) {
        AtomicLong counter = threatCounters.get(sessionId);
        return counter == null ? 0L : counter.get();
    }

    // ── Private Helpers ─────────────────────────────────────────────────────

    private Map<String, Object> buildAlertPayload(PhishingThreat threat) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("alertId",        threat.getId());
        payload.put("type",           "PHISHING_ALERT");
        payload.put("threatLevel",    threat.getThreatLevel().name());
        payload.put("threatType",     threat.getThreatType().name());
        payload.put("confidenceScore", Math.round(threat.getConfidenceScore() * 100));
        payload.put("indicators",     threat.getIndicators());
        payload.put("isDomainSpoofed",threat.isDomainSpoofed());
        payload.put("hasUrgency",     threat.isHasUrgencyLanguage());
        payload.put("detectedBy",     threat.getDetectedBy());
        payload.put("detectedAt",     threat.getDetectedAt()
                                           .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        payload.put("sessionId",      threat.getSessionId());
        payload.put("userId",         threat.getUserId());
        payload.put("soundAlert",     resolveSoundAlert(threat.getThreatLevel()));
        payload.put("popupColor",     resolvePopupColor(threat.getThreatLevel()));
        payload.put("title",          resolveThreatTitle(threat));
        payload.put("message",        buildAlertMessage(threat));
        return payload;
    }

    private String resolveSoundAlert(ThreatLevel level) {
        return switch (level) {
            case CRITICAL -> "ALARM_CRITICAL";
            case HIGH     -> "ALARM_HIGH";
            case MEDIUM   -> "BEEP_WARNING";
            default       -> "NONE";
        };
    }

    private String resolvePopupColor(ThreatLevel level) {
        return switch (level) {
            case CRITICAL -> "#FF1744";
            case HIGH     -> "#FF6D00";
            case MEDIUM   -> "#FFD600";
            default       -> "#00C853";
        };
    }

    private String resolveThreatTitle(PhishingThreat threat) {
        return switch (threat.getThreatLevel()) {
            case CRITICAL -> "CRITICAL THREAT DETECTED";
            case HIGH     -> "High-Risk Phishing Attempt";
            case MEDIUM   -> "Suspicious Activity Warning";
            default       -> "Low Risk Detected";
        };
    }

    private String buildAlertMessage(PhishingThreat threat) {
        String type = threat.getThreatType().name().replace("_", " ");
        int confidence = (int) Math.round(threat.getConfidenceScore() * 100);
        return String.format(
            "%s detected with %d%% confidence. %s",
            type, confidence,
            threat.getIndicators().isEmpty() ? ""
                : "Key indicator: " + threat.getIndicators().get(0)
        );
    }
}
