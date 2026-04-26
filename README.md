🛡️ PhishGuard — AI-Based Phishing Detection System

> Multi-layer AI engine that detects phishing attacks in real time and alerts users with sound alarms and popups immediately after login.

---

Architecture

```
┌─────────────────────────────────────────────────────────┐
│  React Frontend (PhishGuardApp.jsx)                     │
│  • Login screen → triggers post-login passive scan      │
│  • Real-time alert popups + alarm sounds                │
│  • Manual scan panel (URL / email / SMS / domain)       │
│  • Threat history & statistics dashboard                │
└────────────────────┬────────────────────────────────────┘
                     │ REST /api/scan + WebSocket /ws
┌────────────────────▼────────────────────────────────────┐
│  Java Spring Boot Backend                               │
│  PhishGuardController  →  PhishingDetectionService      │
│                                ├── Layer 1: URL Analysis │
│                                ├── Layer 2: NLP Engine   │
│                                ├── Layer 3: Domain Reput.│
│                                └── Layer 4: Homograph    │
│  AlertService → WebSocket STOMP → Frontend popups       │
└─────────────────────────────────────────────────────────┘
```

---

 Backend Setup (Java / Spring Boot)

 Prerequisites
- Java 21+
- Maven 3.9+

 Run
```bash
cd backend
mvn spring-boot:run
```

Server starts on **http://localhost:8080**

Key Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Analyze URL / email / SMS / domain |
| GET | `/api/history` | Recent threats for a session |
| GET | `/api/stats` | Global detection statistics |
| POST | `/api/report` | Report false positive/negative |
| GET | `/api/health` | Liveness probe |
| WS | `/ws` | WebSocket STOMP endpoint |

Example Scan Request
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "content": "http://paypal-secure-login.tk/verify?redirect=http://evil.com",
    "type": "url",
    "userId": "user123",
    "sessionId": "sess-abc",
    "deepScan": false
  }'
```

---
 Frontend Setup (React)

 Prerequisites
- Node 20+ / npm

 Run
```bash
cd frontend
npm install
npm run dev   # or: npm start
```

---

AI Detection Layers

Layer 1 — URL Anatomy Analyzer
- Raw IP address detection
- Suspicious TLD blacklist (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`, `.top`, `.click`, …)
- Brand impersonation in subdomains (PayPal, Amazon, Apple, Google, Microsoft, …)
- Excessive subdomain depth heuristic
- URL shortener detection (bit.ly, tinyurl, …)
- Open redirect chain detection
- Shannon entropy scoring (high-entropy = algorithmically generated domain)
- HTTPS absence flagging

 Layer 2 — NLP Text Classifier
- 20+ urgency/fear phrase detection ("act now", "account suspended", "claim your prize", …)
- Social engineering language scoring
- Excessive capitalization analysis
- Financial lure detection (Bitcoin, wire transfer, gift card)
- Bayesian feature blend

Layer 3 — Domain Reputation
- Known-brand domain spoofing detection
- Newly-registered domain heuristics
- Hyphenated/numeric domain pattern flagging
- (Production: integrate WHOIS/RDAP API for registration age)

Layer 4 — Homograph Attack Detection
- Unicode Cyrillic-to-Latin look-alike character mapping
- Zero false-negative tolerance on homograph patterns

Ensemble Scoring
All four layers produce independent probability scores blended via:
```
blendedScore = A + B × (1 - A)
```
This prevents score inflation while preserving signal from all layers.

---

 Real-Time Alert System

- **WebSocket (STOMP)** — `AlertService` pushes threats to `/topic/alerts/{sessionId}`
- **Sound alerts**: CRITICAL → sawtooth alarm, HIGH → square wave alarm, MEDIUM → sine beep
- **Popup colors**: CRITICAL = #FF1744 (red), HIGH = #FF6D00 (orange), MEDIUM = #FFD600 (yellow)
- **Rate limiting**: 3-second cooldown per session (except CRITICAL — always fires)
- **Admin broadcast**: all threats mirrored to `/topic/admin/threats`

---

 Production Upgrade Path

| Feature | Current | Production |
|---------|---------|------------|
| Persistence | In-memory list | PostgreSQL + Spring Data JPA |
| ML Model | Heuristic rules | ONNX Runtime / TF Java / Hugging Face sidecar |
| Domain intel | Pattern heuristics | WHOIS API + Google Safe Browsing |
| Auth | None | Spring Security + JWT |
| WebSocket broker | In-memory STOMP | RabbitMQ / Redis Pub-Sub |
| Rate limiting | Per-session map | Redis + Bucket4j |

---

Tech Stack
- Backend: Java 21 • Spring Boot 3.2 • Spring WebSocket/STOMP • Maven
- **Frontend**: React 18 • Web Audio API (real alarm sounds) • CSS animations
- **Protocol**: REST JSON + WebSocket STOMP
- **AI**: Multi-layer heuristic ensemble (plug-in trained model in `PhishingDetectionService.java`)
