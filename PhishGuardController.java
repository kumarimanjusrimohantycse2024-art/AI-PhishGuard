package com.phishguard.controller;

import com.phishguard.model.PhishingThreat;
import com.phishguard.model.PhishingThreat.ThreatLevel;
import com.phishguard.model.ScanRequest;
import com.phishguard.service.AlertService;
import com.phishguard.service.PhishingDetectionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * PhishGuard REST API
 *
 * POST /api/scan         — analyze any URL, email, SMS, or domain
 * GET  /api/history      — recent threats for a session
 * GET  /api/stats        — global detection statistics
 * POST /api/report       — submit a false-positive/negative
 * GET  /api/health       — liveness probe
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")   // In production, restrict to your domain
public class PhishGuardController {

    private final PhishingDetectionService detectionService;
    private final AlertService             alertService;

    // In-memory store — replace with JPA/MongoDB in production
    private final List<PhishingThreat> threatHistory = new CopyOnWriteArrayList<>();

    public PhishGuardController(PhishingDetectionService detectionService,
                                 AlertService alertService) {
        this.detectionService = detectionService;
        this.alertService     = alertService;
    }

    // ── POST /api/scan ──────────────────────────────────────────────────────

    @PostMapping("/scan")
    public ResponseEntity<Map<String, Object>> scan(@RequestBody ScanRequest request) {
        if (request.getContent() == null || request.getContent().isBlank()) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Content cannot be empty"));
        }

        long start = System.currentTimeMillis();

        PhishingThreat threat = detectionService.analyze(
            request.getContent(),
            request.getType(),
            request.getUserId(),
            request.getSessionId()
        );

        boolean isThreat = threat.getThreatLevel() != ThreatLevel.LOW;
        if (isThreat) {
            threatHistory.add(threat);
            // Trim history to last 500 entries
            while (threatHistory.size() > 500) threatHistory.remove(0);
        }

        // Fire WebSocket alert for MEDIUM and above
        if (threat.getThreatLevel() != ThreatLevel.LOW) {
            alertService.sendThreatAlert(threat);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("scanId",          threat.getId());
        response.put("isThreat",        isThreat);
        response.put("verdict",         verdict(threat.getThreatLevel()));
        response.put("riskScore",       Math.round(threat.getConfidenceScore() * 100));
        response.put("threatLevel",     threat.getThreatLevel().name());
        response.put("threatType",      isThreat ? threat.getThreatType().name() : null);
        response.put("indicators",      threat.getIndicators());
        response.put("mlFeatures",      threat.getMlFeatures());
        response.put("isDomainSpoofed", threat.isDomainSpoofed());
        response.put("hasUrgencyLang",  threat.isHasUrgencyLanguage());
        response.put("detectedBy",      threat.getDetectedBy());
        response.put("recommendation",  buildRecommendation(threat));
        response.put("scanDurationMs",  System.currentTimeMillis() - start);

        return ResponseEntity.ok(response);
    }

    // ── GET /api/history ────────────────────────────────────────────────────

    @GetMapping("/history")
    public ResponseEntity<Map<String, Object>> history(
            @RequestParam(defaultValue = "") String sessionId,
            @RequestParam(defaultValue = "20") int limit) {

        List<PhishingThreat> filtered = threatHistory.stream()
            .filter(t -> sessionId.isBlank() || sessionId.equals(t.getSessionId()))
            .sorted(Comparator.comparing(PhishingThreat::getDetectedAt).reversed())
            .limit(Math.min(limit, 100))
            .toList();

        return ResponseEntity.ok(Map.of(
            "count",  filtered.size(),
            "threats", filtered.stream().map(this::summarize).toList()
        ));
    }

    // ── GET /api/stats ──────────────────────────────────────────────────────

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> stats() {
        long total    = threatHistory.size();
        long critical = threatHistory.stream().filter(t -> t.getThreatLevel() == ThreatLevel.CRITICAL).count();
        long high     = threatHistory.stream().filter(t -> t.getThreatLevel() == ThreatLevel.HIGH).count();
        long medium   = threatHistory.stream().filter(t -> t.getThreatLevel() == ThreatLevel.MEDIUM).count();

        Map<String, Long> byType = new LinkedHashMap<>();
        for (PhishingThreat.ThreatType type : PhishingThreat.ThreatType.values()) {
            long count = threatHistory.stream().filter(t -> t.getThreatType() == type).count();
            if (count > 0) byType.put(type.name(), count);
        }

        return ResponseEntity.ok(Map.of(
            "totalDetected", total,
            "critical",      critical,
            "high",          high,
            "medium",        medium,
            "byType",        byType,
            "engineVersion", "PhishGuard-Ensemble-v2.1"
        ));
    }

    // ── POST /api/report ────────────────────────────────────────────────────

    @PostMapping("/report")
    public ResponseEntity<Map<String, Object>> report(@RequestBody Map<String, String> body) {
        // In production: store to DB and feed back into model training pipeline
        System.out.printf("[Report] type=%s | content=%s | reporter=%s%n",
            body.get("type"), body.get("content"), body.get("userId"));
        return ResponseEntity.ok(Map.of(
            "accepted", true,
            "message",  "Thank you — your report improves the AI model"
        ));
    }

    // ── GET /api/health ─────────────────────────────────────────────────────

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status",  "UP",
            "service", "PhishGuard AI",
            "version", "2.1.0"
        ));
    }

    // ── Private Helpers ─────────────────────────────────────────────────────

    private String verdict(ThreatLevel level) {
        return switch (level) {
            case CRITICAL -> "PHISHING";
            case HIGH     -> "LIKELY_PHISHING";
            case MEDIUM   -> "SUSPICIOUS";
            case LOW      -> "SAFE";
        };
    }

    private String buildRecommendation(PhishingThreat threat) {
        return switch (threat.getThreatLevel()) {
            case CRITICAL -> "Do NOT click this link. Report it immediately and block the sender.";
            case HIGH     -> "Avoid this content. Verify the sender through official channels only.";
            case MEDIUM   -> "Exercise caution. Do not provide personal or financial information.";
            case LOW      -> "No significant threats detected. Stay vigilant.";
        };
    }

    private Map<String, Object> summarize(PhishingThreat t) {
        return Map.of(
            "id",          t.getId(),
            "threatLevel", t.getThreatLevel().name(),
            "threatType",  t.getThreatType() != null ? t.getThreatType().name() : "UNKNOWN",
            "confidence",  Math.round(t.getConfidenceScore() * 100),
            "detectedAt",  t.getDetectedAt().toString(),
            "topIndicator",t.getIndicators().isEmpty() ? "N/A" : t.getIndicators().get(0)
        );
    }
}
