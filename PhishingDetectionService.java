package com.phishguard.service;

import com.phishguard.model.PhishingThreat;
import com.phishguard.model.PhishingThreat.ThreatLevel;
import com.phishguard.model.PhishingThreat.ThreatType;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * PhishGuard AI Detection Engine
 *
 * Multi-layer phishing detection using:
 *  1. Heuristic rule engine (URL anatomy, entropy, typosquatting)
 *  2. NLP pattern classifier (urgency/fear language, social engineering cues)
 *  3. Domain reputation & homograph detection
 *  4. Bayesian feature scoring ensemble
 *
 * In production, replace the scoring stubs with real trained ML model calls
 * (e.g., via ONNX Runtime, TensorFlow Java, or a REST sidecar).
 */
@Service
public class PhishingDetectionService {

    // ── Suspicious TLD list ──────────────────────────────────────────────────
    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
        ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top", ".click",
        ".link", ".download", ".stream", ".win", ".racing", ".date", ".party"
    );

    // ── Trusted brand names commonly spoofed ────────────────────────────────
    private static final Set<String> SPOOFED_BRANDS = Set.of(
        "paypal", "amazon", "apple", "google", "microsoft", "facebook",
        "instagram", "netflix", "bank", "secure", "account", "verify",
        "update", "signin", "login", "ebay", "wellsfargo", "chase",
        "irs", "fedex", "ups", "usps", "dhl", "covid", "irs"
    );

    // ── Urgency / social-engineering keywords ────────────────────────────────
    private static final List<String> URGENCY_PHRASES = List.of(
        "act now", "urgent", "immediately", "account suspended",
        "verify your identity", "confirm your details", "limited time",
        "click here", "you have won", "claim your prize", "password expired",
        "unusual activity", "suspicious login", "will be terminated",
        "24 hours", "48 hours", "action required", "final notice",
        "update payment", "your account", "reset your password"
    );

    // ── Malicious URL patterns ───────────────────────────────────────────────
    private static final List<Pattern> MALICIOUS_URL_PATTERNS = List.of(
        Pattern.compile(".*@.*\\..*"),                          // user-info in URL
        Pattern.compile(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*"), // raw IP
        Pattern.compile(".*-{2,}.*"),                           // multiple hyphens
        Pattern.compile(".*(secure|login|verify|update|account|bank|confirm).*\\..*\\..*"), // subdomain tricks
        Pattern.compile(".*bit\\.ly.*|.*tinyurl.*|.*ow\\.ly.*|.*goo\\.gl.*"), // URL shorteners
        Pattern.compile(".*\\.php\\?.*"),                       // PHP redirect params
        Pattern.compile(".*redirect=.*|.*url=http.*|.*goto=.*") // open redirects
    );

    // ── Homograph look-alike characters ─────────────────────────────────────
    private static final Map<Character, Character> HOMOGRAPH_MAP = Map.of(
        'а', 'a', 'е', 'e', 'о', 'o', 'р', 'p', 'с', 'c',
        'і', 'i', 'ԁ', 'd', 'ɡ', 'g', 'ʏ', 'y', 'ʍ', 'w'
    );

    // ────────────────────────────────────────────────────────────────────────
    //  PUBLIC API
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Main detection pipeline — runs all layers and returns a scored threat.
     */
    public PhishingThreat analyze(String content, String type, String userId, String sessionId) {
        long start = System.currentTimeMillis();

        PhishingThreat threat = new PhishingThreat();
        threat.setRawInput(content);
        threat.setUserId(userId);
        threat.setSessionId(sessionId);

        List<String> indicators = new ArrayList<>();
        List<String> mlFeatures = new ArrayList<>();
        double score = 0.0;

        // ── Layer 1: URL analysis ─────────────────────────────────────────
        if (type == null || type.equalsIgnoreCase("url") || type.equalsIgnoreCase("auto")) {
            double urlScore = analyzeUrl(content, indicators, mlFeatures);
            score = Math.max(score, urlScore);
        }

        // ── Layer 2: NLP / text analysis ─────────────────────────────────
        double nlpScore = analyzeText(content, indicators, mlFeatures);
        score = blendScores(score, nlpScore);

        // ── Layer 3: Domain reputation ───────────────────────────────────
        double domainScore = analyzeDomain(content, indicators, mlFeatures, threat);
        score = blendScores(score, domainScore);

        // ── Layer 4: Homograph / look-alike detection ─────────────────────
        double homographScore = detectHomograph(content, indicators, mlFeatures);
        score = blendScores(score, homographScore);

        // ── Ensemble final scoring ────────────────────────────────────────
        threat.setConfidenceScore(Math.min(score, 1.0));
        threat.setThreatLevel(classifyThreatLevel(score));
        threat.setThreatType(inferThreatType(content, indicators));
        threat.setIndicators(indicators);
        threat.setMlFeatures(mlFeatures);
        threat.setHasUrgencyLanguage(indicators.stream().anyMatch(i -> i.contains("urgency")));
        threat.setDetectedBy("PhishGuard-Ensemble-v2.1");

        System.out.printf("[PhishGuard] Scanned in %dms | score=%.3f | level=%s | input=%s%n",
            System.currentTimeMillis() - start,
            score,
            threat.getThreatLevel(),
            content.length() > 60 ? content.substring(0, 60) + "…" : content
        );

        return threat;
    }

    // ────────────────────────────────────────────────────────────────────────
    //  LAYER 1 — URL Analysis
    // ────────────────────────────────────────────────────────────────────────

    private double analyzeUrl(String url, List<String> indicators, List<String> features) {
        double score = 0.0;
        String lower = url.toLowerCase();

        // Raw IP address
        if (lower.matches(".*https?://\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            score += 0.45;
            indicators.add("Raw IP address used instead of domain name");
            features.add("RAW_IP_HOST");
        }

        // Suspicious TLD
        for (String tld : SUSPICIOUS_TLDS) {
            if (lower.contains(tld)) {
                score += 0.30;
                indicators.add("Suspicious TLD: " + tld);
                features.add("SUSPICIOUS_TLD:" + tld);
                break;
            }
        }

        // Malicious URL patterns
        for (Pattern pattern : MALICIOUS_URL_PATTERNS) {
            if (pattern.matcher(lower).matches()) {
                score += 0.25;
                indicators.add("Malicious URL pattern detected");
                features.add("MALICIOUS_PATTERN");
                break;
            }
        }

        // Excessive subdomains (e.g., paypal.secure.login.evil.com)
        try {
            URI uri = new URI(url.startsWith("http") ? url : "http://" + url);
            String host = uri.getHost();
            if (host != null) {
                String[] parts = host.split("\\.");
                if (parts.length >= 4) {
                    score += 0.20;
                    indicators.add("Excessive subdomains — possible domain spoofing");
                    features.add("EXCESSIVE_SUBDOMAINS:" + parts.length);
                }
                // Check for brand in subdomain
                for (String brand : SPOOFED_BRANDS) {
                    if (parts.length > 2 && Arrays.stream(parts).limit(parts.length - 2)
                            .anyMatch(p -> p.contains(brand))) {
                        score += 0.40;
                        indicators.add("Brand name '" + brand + "' found in subdomain — likely spoofing");
                        features.add("BRAND_IN_SUBDOMAIN:" + brand);
                        break;
                    }
                }
            }
        } catch (Exception ignored) {}

        // URL entropy (randomly-generated domains have high entropy)
        double entropy = calculateEntropy(lower);
        if (entropy > 3.9) {
            score += 0.15;
            indicators.add("High domain entropy — possible algorithmically-generated domain");
            features.add("HIGH_ENTROPY:" + String.format("%.2f", entropy));
        }

        // HTTPS absence
        if (!lower.startsWith("https://")) {
            score += 0.10;
            indicators.add("No HTTPS — connection is unencrypted");
            features.add("NO_HTTPS");
        }

        // Redirect chains
        if (lower.contains("redirect=") || lower.contains("url=http") || lower.contains("goto=")) {
            score += 0.30;
            indicators.add("Open redirect chain detected");
            features.add("OPEN_REDIRECT");
        }

        return Math.min(score, 1.0);
    }

    // ────────────────────────────────────────────────────────────────────────
    //  LAYER 2 — NLP / Text Analysis
    // ────────────────────────────────────────────────────────────────────────

    private double analyzeText(String text, List<String> indicators, List<String> features) {
        double score = 0.0;
        String lower = text.toLowerCase();
        int urgencyHits = 0;

        for (String phrase : URGENCY_PHRASES) {
            if (lower.contains(phrase)) {
                urgencyHits++;
                features.add("URGENCY_PHRASE:" + phrase.replace(" ", "_"));
            }
        }

        if (urgencyHits > 0) {
            score += Math.min(urgencyHits * 0.12, 0.55);
            indicators.add("Urgency language detected (" + urgencyHits + " phrases) — classic social engineering");
            features.add("URGENCY_HIT_COUNT:" + urgencyHits);
        }

        // Excessive punctuation / ALL CAPS
        long capsWords = Arrays.stream(text.split("\\s+"))
            .filter(w -> w.length() > 3 && w.equals(w.toUpperCase())).count();
        if (capsWords >= 3) {
            score += 0.10;
            indicators.add("Excessive capitalization — designed to create panic");
            features.add("EXCESSIVE_CAPS:" + capsWords);
        }

        // Dollar / financial lure
        if (lower.contains("$") || lower.contains("wire transfer") || lower.contains("bitcoin")
                || lower.contains("gift card")) {
            score += 0.20;
            indicators.add("Financial lure detected (money, transfer, crypto)");
            features.add("FINANCIAL_LURE");
        }

        return Math.min(score, 1.0);
    }

    // ────────────────────────────────────────────────────────────────────────
    //  LAYER 3 — Domain Reputation
    // ────────────────────────────────────────────────────────────────────────

    private double analyzeDomain(String input, List<String> indicators, List<String> features,
                                  PhishingThreat threat) {
        double score = 0.0;
        String lower = input.toLowerCase();

        for (String brand : SPOOFED_BRANDS) {
            if (lower.contains(brand)) {
                // Check if it's a known-safe domain (very naive check — use RDAP/WHOIS in prod)
                boolean trustedContext = lower.contains(brand + ".com") && !lower.contains("-" + brand)
                    && !lower.contains(brand + "-");
                if (!trustedContext) {
                    score += 0.35;
                    threat.setDomainSpoofed(true);
                    indicators.add("Domain impersonates trusted brand: " + brand);
                    features.add("DOMAIN_SPOOFING:" + brand);
                    break;
                }
            }
        }

        // Newly-registered domain signal (heuristic: numeric or hyphenated TLDs)
        if (lower.matches(".*-\\d{4,}.*") || lower.matches(".*\\d{6,}.*")) {
            score += 0.20;
            indicators.add("Possible newly-registered or auto-generated domain");
            features.add("SUSPICIOUS_DOMAIN_PATTERN");
        }

        return Math.min(score, 1.0);
    }

    // ────────────────────────────────────────────────────────────────────────
    //  LAYER 4 — Homograph / Look-alike Detection
    // ────────────────────────────────────────────────────────────────────────

    private double detectHomograph(String input, List<String> indicators, List<String> features) {
        boolean found = false;
        for (char c : input.toCharArray()) {
            if (HOMOGRAPH_MAP.containsKey(c)) {
                found = true;
                break;
            }
        }
        if (found) {
            indicators.add("Homograph attack — Cyrillic/Unicode characters disguised as Latin letters");
            features.add("HOMOGRAPH_ATTACK");
            return 0.80;
        }
        return 0.0;
    }

    // ────────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ────────────────────────────────────────────────────────────────────────

    /** Weighted blending to avoid simple addition overflow. */
    private double blendScores(double a, double b) {
        return a + b * (1.0 - a);
    }

    /** Shannon entropy of a string. */
    private double calculateEntropy(String s) {
        Map<Character, Long> freq = s.chars().mapToObj(c -> (char) c)
            .collect(Collectors.groupingBy(c -> c, Collectors.counting()));
        double entropy = 0;
        for (long count : freq.values()) {
            double p = (double) count / s.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private ThreatLevel classifyThreatLevel(double score) {
        if (score >= 0.80) return ThreatLevel.CRITICAL;
        if (score >= 0.55) return ThreatLevel.HIGH;
        if (score >= 0.30) return ThreatLevel.MEDIUM;
        return ThreatLevel.LOW;
    }

    private ThreatType inferThreatType(String content, List<String> indicators) {
        String lower = content.toLowerCase();
        String joined = String.join(" ", indicators).toLowerCase();
        if (joined.contains("homograph"))        return ThreatType.HOMOGRAPH_ATTACK;
        if (joined.contains("subdomain"))        return ThreatType.TYPOSQUATTING;
        if (lower.contains("@"))                 return ThreatType.EMAIL_PHISHING;
        if (lower.startsWith("sms") || lower.startsWith("+")) return ThreatType.SMISHING;
        if (joined.contains("brand"))            return ThreatType.CLONE_PHISHING;
        return ThreatType.URL_PHISHING;
    }
}
