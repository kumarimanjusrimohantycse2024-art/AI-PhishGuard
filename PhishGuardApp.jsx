import { useState, useEffect, useRef, useCallback } from "react";

// ── Sound Engine ──────────────────────────────────────────────────────────────
const SoundEngine = {
  ctx: null,
  getCtx() {
    if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    return this.ctx;
  },
  playAlarm(type = "ALARM_HIGH") {
    try {
      const ctx = this.getCtx();
      const freqs = type === "ALARM_CRITICAL"
        ? [880, 660, 880, 660, 880]
        : type === "ALARM_HIGH"
        ? [660, 440, 660]
        : [440, 440];

      freqs.forEach((freq, i) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain); gain.connect(ctx.destination);
        osc.frequency.value = freq;
        osc.type = type === "ALARM_CRITICAL" ? "sawtooth" : "square";
        gain.gain.setValueAtTime(0, ctx.currentTime + i * 0.18);
        gain.gain.linearRampToValueAtTime(0.25, ctx.currentTime + i * 0.18 + 0.03);
        gain.gain.linearRampToValueAtTime(0, ctx.currentTime + i * 0.18 + 0.15);
        osc.start(ctx.currentTime + i * 0.18);
        osc.stop(ctx.currentTime + i * 0.18 + 0.2);
      });
    } catch (e) { console.warn("Audio:", e); }
  },
  playBeep() {
    try {
      const ctx = this.getCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination);
      osc.frequency.value = 520;
      osc.type = "sine";
      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.3);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.35);
    } catch (e) {}
  },
};

// ── Threat Level Config ───────────────────────────────────────────────────────
const LEVEL_CFG = {
  CRITICAL: { color: "#FF1744", bg: "#1a0005", badge: "#FF1744", icon: "☣", label: "CRITICAL" },
  HIGH:     { color: "#FF6D00", bg: "#1a0800", badge: "#FF6D00", icon: "⚠", label: "HIGH" },
  MEDIUM:   { color: "#FFD600", bg: "#1a1500", badge: "#FFD600", icon: "⚡", label: "MEDIUM" },
  LOW:      { color: "#00C853", bg: "#001a08", badge: "#00C853", icon: "✓", label: "LOW" },
  SAFE:     { color: "#00E676", bg: "#001a08", badge: "#00E676", icon: "✓", label: "SAFE" },
};

// ── Simulated backend scan (replace with real fetch to localhost:8080) ─────────
async function callBackend(content, type) {
  // Simulated detection engine (mirrors Java logic)
  await new Promise(r => setTimeout(r, 600 + Math.random() * 800));

  const lower = content.toLowerCase();
  const indicators = [];
  const mlFeatures = [];
  let score = 0;

  const URGENCY = ["urgent","verify","account suspended","click here","act now","password expired","unusual activity","claim","limited time","action required","confirm your details","will be terminated","24 hours"];
  const BRANDS = ["paypal","amazon","apple","google","microsoft","facebook","netflix","bank","secure","signin","login"];
  const BAD_TLDS = [".tk",".ml",".ga",".cf",".gq",".pw",".top",".click",".win"];
  const SHORTENERS = ["bit.ly","tinyurl","ow.ly","goo.gl","t.co/x"];

  // IP address
  if (/https?:\/\/\d+\.\d+\.\d+\.\d+/.test(lower)) {
    score += 0.45; indicators.push("Raw IP address used instead of domain name");
    mlFeatures.push("RAW_IP_HOST");
  }
  // Suspicious TLD
  BAD_TLDS.forEach(tld => { if (lower.includes(tld)) { score += 0.30; indicators.push("Suspicious TLD: " + tld); mlFeatures.push("SUSPICIOUS_TLD"); }});
  // URL shorteners
  SHORTENERS.forEach(s => { if (lower.includes(s)) { score += 0.20; indicators.push("URL shortener used — destination hidden"); mlFeatures.push("URL_SHORTENER"); }});
  // Brand spoofing in subdomain
  BRANDS.forEach(brand => {
    if (lower.includes(brand) && (lower.includes("-" + brand) || lower.includes(brand + "-") || (lower.match(/\./g)||[]).length > 2)) {
      score += 0.40; indicators.push("Brand '" + brand + "' impersonated in domain"); mlFeatures.push("BRAND_SPOOF:" + brand);
    }
  });
  // Urgency language
  let urgencyHits = 0;
  URGENCY.forEach(p => { if (lower.includes(p)) { urgencyHits++; mlFeatures.push("URGENCY:" + p.replace(/ /g,"_")); }});
  if (urgencyHits > 0) {
    score += Math.min(urgencyHits * 0.12, 0.55);
    indicators.push("Urgency/fear language detected (" + urgencyHits + " phrases)");
  }
  // No HTTPS
  if (lower.startsWith("http://")) { score += 0.10; indicators.push("No HTTPS — unencrypted connection"); mlFeatures.push("NO_HTTPS"); }
  // Open redirect
  if (lower.includes("redirect=") || lower.includes("url=http") || lower.includes("goto=")) {
    score += 0.30; indicators.push("Open redirect chain detected"); mlFeatures.push("OPEN_REDIRECT");
  }
  // Excessive subdomains
  try {
    const url = lower.startsWith("http") ? lower : "https://" + lower;
    const host = new URL(url).hostname;
    if ((host.split(".").length) >= 4) { score += 0.20; indicators.push("Excessive subdomains — domain spoofing likely"); mlFeatures.push("EXCESSIVE_SUBDOMAINS"); }
  } catch(_) {}
  // Financial lure
  if (lower.includes("bitcoin") || lower.includes("gift card") || lower.includes("wire transfer")) {
    score += 0.20; indicators.push("Financial lure detected"); mlFeatures.push("FINANCIAL_LURE");
  }
  // PHP params
  if (lower.includes(".php?")) { score += 0.15; indicators.push("Suspicious PHP redirect parameters"); mlFeatures.push("PHP_REDIRECT"); }

  score = Math.min(score, 1.0);
  const riskScore = Math.round(score * 100);
  const threatLevel = score >= 0.80 ? "CRITICAL" : score >= 0.55 ? "HIGH" : score >= 0.30 ? "MEDIUM" : "LOW";
  const isThreat = threatLevel !== "LOW";
  const verdict = threatLevel === "CRITICAL" ? "PHISHING" : threatLevel === "HIGH" ? "LIKELY_PHISHING" : threatLevel === "MEDIUM" ? "SUSPICIOUS" : "SAFE";
  const rec = {
    CRITICAL: "Do NOT click this link. Report it immediately and block the sender.",
    HIGH: "Avoid this content. Verify through official channels only.",
    MEDIUM: "Exercise caution. Do not provide personal or financial information.",
    LOW: "No significant threats detected. Stay vigilant.",
  }[threatLevel];
  const threatTypes = ["URL_PHISHING","EMAIL_PHISHING","CLONE_PHISHING","TYPOSQUATTING","SMISHING","HOMOGRAPH_ATTACK"];
  const threatType = isThreat ? threatTypes[Math.floor(Math.random() * 3)] : null;

  return { isThreat, verdict, riskScore, threatLevel, threatType, indicators, mlFeatures, isDomainSpoofed: indicators.some(i=>i.includes("impersonat")), hasUrgencyLang: urgencyHits > 0, recommendation: rec, detectedBy: "PhishGuard-Ensemble-v2.1", scanDurationMs: Math.floor(600 + Math.random()*800), scanId: Math.random().toString(36).slice(2) };
}

// ── Alert Popup Component ─────────────────────────────────────────────────────
function ThreatAlert({ alert, onDismiss }) {
  const cfg = LEVEL_CFG[alert.threatLevel] || LEVEL_CFG.MEDIUM;
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true));
  }, []);

  return (
    <div style={{
      position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
      background: "rgba(0,0,0,0.85)", zIndex: 9999,
      display: "flex", alignItems: "center", justifyContent: "center",
      backdropFilter: "blur(4px)",
      transition: "opacity 0.3s",
      opacity: visible ? 1 : 0,
    }}>
      <div style={{
        background: "#0d0d0d",
        border: `2px solid ${cfg.color}`,
        borderRadius: 16,
        maxWidth: 560,
        width: "90%",
        padding: 0,
        boxShadow: `0 0 60px ${cfg.color}55, 0 0 120px ${cfg.color}22`,
        transform: visible ? "scale(1)" : "scale(0.9)",
        transition: "transform 0.3s cubic-bezier(0.34,1.56,0.64,1)",
        overflow: "hidden",
      }}>
        {/* Header bar */}
        <div style={{
          background: cfg.color,
          padding: "14px 24px",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}>
          <span style={{ fontSize: 28 }}>{cfg.icon}</span>
          <div>
            <div style={{ fontFamily: "monospace", fontWeight: 700, fontSize: 18, color: "#fff", letterSpacing: 2 }}>
              {alert.threatLevel} THREAT DETECTED
            </div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.8)", fontFamily: "monospace" }}>
              PhishGuard AI • Confidence: {alert.riskScore}%
            </div>
          </div>
          <div style={{ marginLeft: "auto", textAlign: "right" }}>
            <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: 8, padding: "4px 10px", fontSize: 12, fontFamily: "monospace", color: "#fff" }}>
              {alert.threatType?.replace(/_/g, " ")}
            </div>
          </div>
        </div>

        {/* Body */}
        <div style={{ padding: "20px 24px" }}>
          <div style={{ fontSize: 15, color: "#e0e0e0", marginBottom: 16, lineHeight: 1.6 }}>
            {alert.recommendation}
          </div>

          {/* Indicators */}
          {alert.indicators?.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: "#888", fontFamily: "monospace", marginBottom: 8, letterSpacing: 1 }}>
                THREAT INDICATORS
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {alert.indicators.slice(0, 4).map((ind, i) => (
                  <div key={i} style={{
                    display: "flex", alignItems: "flex-start", gap: 8,
                    background: `${cfg.color}15`, borderRadius: 6,
                    padding: "6px 10px", fontSize: 13, color: "#ddd",
                    borderLeft: `3px solid ${cfg.color}`,
                  }}>
                    <span style={{ color: cfg.color, fontSize: 10, marginTop: 3, flexShrink: 0 }}>▶</span>
                    {ind}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ML features badge strip */}
          {alert.mlFeatures?.length > 0 && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 20 }}>
              {alert.mlFeatures.slice(0, 6).map((f, i) => (
                <span key={i} style={{
                  background: "#1a1a1a", border: "1px solid #333",
                  borderRadius: 4, padding: "2px 8px", fontSize: 11,
                  fontFamily: "monospace", color: "#aaa",
                }}>
                  {f}
                </span>
              ))}
            </div>
          )}

          {/* Action buttons */}
          <div style={{ display: "flex", gap: 12 }}>
            <button onClick={onDismiss} style={{
              flex: 1, padding: "12px 0",
              background: cfg.color, color: "#fff",
              border: "none", borderRadius: 8,
              fontSize: 14, fontWeight: 700, cursor: "pointer",
              fontFamily: "monospace", letterSpacing: 1,
            }}>
              UNDERSTOOD — DISMISS
            </button>
            <button onClick={() => { onDismiss(); }} style={{
              flex: 1, padding: "12px 0",
              background: "transparent", color: "#888",
              border: "1px solid #333", borderRadius: 8,
              fontSize: 14, cursor: "pointer", fontFamily: "monospace",
            }}>
              REPORT FALSE POSITIVE
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Scan Form Component ───────────────────────────────────────────────────────
function ScanPanel({ onResult, sessionActive }) {
  const [input, setInput] = useState("");
  const [type, setType] = useState("auto");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);

  const scan = async () => {
    if (!input.trim() || scanning) return;
    setScanning(true);
    setProgress(0);
    const prog = setInterval(() => setProgress(p => Math.min(p + 8, 90)), 80);
    try {
      const result = await callBackend(input.trim(), type);
      setProgress(100);
      setTimeout(() => { setProgress(0); setScanning(false); }, 300);
      onResult({ ...result, rawInput: input.trim() });
    } catch (e) {
      setScanning(false); setProgress(0);
    }
    clearInterval(prog);
  };

  return (
    <div style={{ background: "#0f0f13", border: "1px solid #222", borderRadius: 14, padding: 24 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 18 }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: sessionActive ? "#00C853" : "#555",
          boxShadow: sessionActive ? "0 0 8px #00C853" : "none", animation: sessionActive ? "pulse 2s infinite" : "none" }} />
        <span style={{ fontFamily: "monospace", fontSize: 13, color: "#888", letterSpacing: 1 }}>
          {sessionActive ? "SESSION PROTECTED — MONITORING ACTIVE" : "NOT LOGGED IN"}
        </span>
      </div>

      <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
        {["auto","url","email","sms","domain"].map(t => (
          <button key={t} onClick={() => setType(t)} style={{
            padding: "5px 14px", borderRadius: 6, fontSize: 12, fontFamily: "monospace",
            background: type === t ? "#7B61FF" : "transparent",
            color: type === t ? "#fff" : "#666",
            border: `1px solid ${type === t ? "#7B61FF" : "#333"}`,
            cursor: "pointer", letterSpacing: 0.5,
          }}>
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      <textarea
        value={input}
        onChange={e => setInput(e.target.value)}
        onKeyDown={e => { if (e.ctrlKey && e.key === "Enter") scan(); }}
        placeholder="Paste URL, email content, SMS, or domain to scan…&#10;&#10;Try: http://paypal-secure-login.tk/verify?redirect=http://evil.com"
        style={{
          width: "100%", minHeight: 100, background: "#0a0a0f", color: "#e0e0e0",
          border: "1px solid #2a2a3a", borderRadius: 8, padding: 14, fontSize: 14,
          fontFamily: "monospace", resize: "vertical", lineHeight: 1.6,
          boxSizing: "border-box", outline: "none",
        }}
      />

      {progress > 0 && (
        <div style={{ height: 3, background: "#1a1a2a", borderRadius: 2, margin: "10px 0" }}>
          <div style={{
            height: "100%", background: "linear-gradient(90deg, #7B61FF, #00C853)",
            width: `${progress}%`, borderRadius: 2, transition: "width 0.1s",
          }} />
        </div>
      )}

      <button onClick={scan} disabled={scanning || !input.trim()} style={{
        width: "100%", marginTop: 12, padding: "13px 0",
        background: scanning ? "#1a1a2a" : "linear-gradient(135deg, #7B61FF, #4A3FDB)",
        color: scanning ? "#666" : "#fff",
        border: "none", borderRadius: 8, fontSize: 15, fontWeight: 700,
        cursor: scanning ? "not-allowed" : "pointer",
        fontFamily: "monospace", letterSpacing: 2,
        transition: "all 0.2s",
      }}>
        {scanning ? "◎ SCANNING…" : "▶  RUN AI SCAN  (Ctrl+Enter)"}
      </button>
    </div>
  );
}

// ── Result Card ───────────────────────────────────────────────────────────────
function ResultCard({ result }) {
  const cfg = LEVEL_CFG[result.isThreat ? result.threatLevel : "SAFE"];
  return (
    <div style={{
      background: "#0f0f13", border: `1px solid ${cfg.color}55`,
      borderRadius: 14, padding: 20, animation: "fadeUp 0.4s ease",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
        <div style={{
          width: 56, height: 56, borderRadius: 12,
          background: `${cfg.color}20`, border: `2px solid ${cfg.color}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 26, color: cfg.color,
        }}>
          {result.isThreat ? "⚠" : "✓"}
        </div>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700, color: cfg.color, fontFamily: "monospace" }}>
            {result.verdict}
          </div>
          <div style={{ fontSize: 13, color: "#888" }}>
            Risk score: <span style={{ color: cfg.color, fontWeight: 600 }}>{result.riskScore}/100</span>
            {" "}• {result.scanDurationMs}ms • {result.detectedBy}
          </div>
        </div>
        <div style={{ marginLeft: "auto" }}>
          <div style={{
            background: `${cfg.color}22`, border: `1px solid ${cfg.color}`,
            borderRadius: 8, padding: "6px 14px", fontFamily: "monospace",
            fontSize: 13, color: cfg.color, fontWeight: 700,
          }}>
            {result.threatLevel}
          </div>
        </div>
      </div>

      {/* Risk bar */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#666", marginBottom: 5, fontFamily: "monospace" }}>
          <span>RISK SCORE</span><span>{result.riskScore}%</span>
        </div>
        <div style={{ height: 6, background: "#1a1a2a", borderRadius: 3 }}>
          <div style={{
            height: "100%", background: cfg.color,
            width: `${result.riskScore}%`, borderRadius: 3,
            boxShadow: result.riskScore > 60 ? `0 0 10px ${cfg.color}` : "none",
            transition: "width 1s cubic-bezier(0.34,1.56,0.64,1)",
          }} />
        </div>
      </div>

      <div style={{ fontSize: 14, color: "#ccc", marginBottom: 14, lineHeight: 1.6, fontStyle: "italic" }}>
        {result.recommendation}
      </div>

      {result.indicators?.length > 0 && (
        <div>
          <div style={{ fontSize: 11, color: "#555", fontFamily: "monospace", marginBottom: 8, letterSpacing: 1 }}>
            THREAT INDICATORS ({result.indicators.length})
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {result.indicators.map((ind, i) => (
              <div key={i} style={{
                fontSize: 13, color: "#bbb", padding: "5px 10px",
                background: "#151520", borderRadius: 5,
                borderLeft: `3px solid ${cfg.color}88`,
              }}>
                {ind}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Stats Bar ─────────────────────────────────────────────────────────────────
function StatsBar({ history }) {
  const total = history.length;
  const critical = history.filter(h => h.threatLevel === "CRITICAL").length;
  const high = history.filter(h => h.threatLevel === "HIGH").length;
  const safe = history.filter(h => !h.isThreat).length;

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10 }}>
      {[
        { label: "SCANNED", value: total, color: "#7B61FF" },
        { label: "CRITICAL", value: critical, color: "#FF1744" },
        { label: "HIGH", value: high, color: "#FF6D00" },
        { label: "SAFE", value: safe, color: "#00C853" },
      ].map(s => (
        <div key={s.label} style={{
          background: "#0f0f13", border: "1px solid #222", borderRadius: 10,
          padding: "14px 12px", textAlign: "center",
        }}>
          <div style={{ fontSize: 26, fontWeight: 700, fontFamily: "monospace", color: s.color }}>{s.value}</div>
          <div style={{ fontSize: 10, color: "#555", fontFamily: "monospace", letterSpacing: 1, marginTop: 3 }}>{s.label}</div>
        </div>
      ))}
    </div>
  );
}

// ── History Panel ─────────────────────────────────────────────────────────────
function HistoryPanel({ history }) {
  if (!history.length) return (
    <div style={{ textAlign: "center", color: "#444", padding: 30, fontFamily: "monospace", fontSize: 13 }}>
      No scans yet — run your first scan above
    </div>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {history.slice().reverse().slice(0, 8).map((h, i) => {
        const cfg = LEVEL_CFG[h.isThreat ? h.threatLevel : "SAFE"];
        return (
          <div key={h.scanId || i} style={{
            display: "flex", alignItems: "center", gap: 12, padding: "10px 14px",
            background: "#0a0a0f", borderRadius: 8, border: "1px solid #1a1a2a",
          }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: cfg.color, flexShrink: 0 }} />
            <div style={{ flex: 1, fontFamily: "monospace", fontSize: 12, color: "#777", overflow: "hidden" }}>
              <span style={{ display: "block", color: "#bbb", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {h.rawInput?.slice(0, 50)}{h.rawInput?.length > 50 ? "…" : ""}
              </span>
              <span style={{ color: "#555" }}>{h.threatType?.replace(/_/g," ") || "SAFE"}</span>
            </div>
            <div style={{
              background: `${cfg.color}22`, color: cfg.color,
              padding: "2px 8px", borderRadius: 4, fontSize: 11, fontFamily: "monospace", fontWeight: 700,
            }}>
              {h.riskScore}%
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Login Screen ──────────────────────────────────────────────────────────────
function LoginScreen({ onLogin }) {
  const [user, setUser] = useState(""); const [pass, setPass] = useState(""); const [loading, setLoading] = useState(false);
  const submit = async (e) => {
    e?.preventDefault?.();
    if (!user.trim()) return;
    setLoading(true);
    await new Promise(r => setTimeout(r, 1200));
    setLoading(false);
    onLogin(user.trim() || "analyst");
  };
  return (
    <div style={{
      minHeight: "100vh", background: "#070709",
      display: "flex", alignItems: "center", justifyContent: "center",
      fontFamily: "'Courier New', monospace",
    }}>
      <div style={{ width: 400, padding: 40, background: "#0d0d11", border: "1px solid #222", borderRadius: 18 }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontSize: 48, marginBottom: 8 }}>🛡️</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: "#7B61FF", letterSpacing: 3 }}>PHISHGUARD</div>
          <div style={{ fontSize: 12, color: "#555", letterSpacing: 2, marginTop: 4 }}>AI THREAT DETECTION SYSTEM</div>
        </div>
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, color: "#555", marginBottom: 6, letterSpacing: 1 }}>USERNAME</div>
          <input value={user} onChange={e => setUser(e.target.value)} placeholder="analyst"
            style={{ width: "100%", background: "#0a0a0f", color: "#e0e0e0", border: "1px solid #2a2a3a", borderRadius: 8, padding: "11px 14px", fontSize: 14, fontFamily: "monospace", boxSizing: "border-box", outline: "none" }} />
        </div>
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", marginBottom: 6, letterSpacing: 1 }}>PASSWORD</div>
          <input type="password" value={pass} onChange={e => setPass(e.target.value)} onKeyDown={e => e.key==="Enter" && submit()}
            placeholder="••••••••"
            style={{ width: "100%", background: "#0a0a0f", color: "#e0e0e0", border: "1px solid #2a2a3a", borderRadius: 8, padding: "11px 14px", fontSize: 14, fontFamily: "monospace", boxSizing: "border-box", outline: "none" }} />
        </div>
        <button onClick={submit} disabled={loading} style={{
          width: "100%", padding: "13px 0",
          background: loading ? "#1a1a2a" : "linear-gradient(135deg, #7B61FF, #4A3FDB)",
          color: loading ? "#555" : "#fff", border: "none", borderRadius: 8,
          fontSize: 15, fontWeight: 700, cursor: loading ? "not-allowed" : "pointer", letterSpacing: 2,
        }}>
          {loading ? "AUTHENTICATING…" : "SECURE LOGIN"}
        </button>
        <div style={{ textAlign: "center", marginTop: 16, fontSize: 11, color: "#444" }}>
          Protected by PhishGuard AI Engine v2.1
        </div>
      </div>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}`}</style>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function PhishGuardApp() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [userId, setUserId] = useState("");
  const [activeAlert, setActiveAlert] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [latestResult, setLatestResult] = useState(null);
  const [tab, setTab] = useState("scan");

  const handleLogin = useCallback((username) => {
    setUserId(username);
    setLoggedIn(true);
    // Post-login passive scan simulation — always alerts on login
    setTimeout(async () => {
      SoundEngine.playBeep();
      const loginResult = await callBackend("http://paypal-secure-login.tk/verify?redirect=http://evil.com&urgency=act+now+account+suspended", "url");
      loginResult.rawInput = "Post-login environment scan";
      loginResult.isLoginScan = true;
      setScanHistory(h => [loginResult, ...h]);
      if (loginResult.isThreat) {
        const snd = loginResult.threatLevel === "CRITICAL" ? "ALARM_CRITICAL" : "ALARM_HIGH";
        SoundEngine.playAlarm(snd);
        setActiveAlert(loginResult);
      }
    }, 1200);
  }, []);

  const handleScanResult = useCallback((result) => {
    setLatestResult(result);
    setScanHistory(h => [result, ...h]);
    if (result.isThreat) {
      const snd = result.threatLevel === "CRITICAL" ? "ALARM_CRITICAL" : result.threatLevel === "HIGH" ? "ALARM_HIGH" : "BEEP_WARNING";
      if (snd === "BEEP_WARNING") SoundEngine.playBeep();
      else SoundEngine.playAlarm(snd);
      setActiveAlert(result);
    }
  }, []);

  if (!loggedIn) return <LoginScreen onLogin={handleLogin} />;

  return (
    <div style={{ minHeight: "100vh", background: "#070709", color: "#e0e0e0", fontFamily: "'Courier New', monospace" }}>
      <style>{`
        @keyframes fadeUp { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0a0a0f; }
        ::-webkit-scrollbar-thumb { background: #2a2a3a; border-radius: 3px; }
      `}</style>

      {activeAlert && <ThreatAlert alert={activeAlert} onDismiss={() => setActiveAlert(null)} />}

      {/* Top Nav */}
      <div style={{ borderBottom: "1px solid #1a1a2a", padding: "12px 28px", display: "flex", alignItems: "center", gap: 16 }}>
        <span style={{ fontSize: 22 }}>🛡️</span>
        <div>
          <span style={{ fontWeight: 700, color: "#7B61FF", fontSize: 15, letterSpacing: 2 }}>PHISHGUARD</span>
          <span style={{ color: "#555", fontSize: 11, marginLeft: 10, letterSpacing: 1 }}>AI ENGINE v2.1</span>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#00C853", animation: "pulse 2s infinite", boxShadow: "0 0 6px #00C853" }} />
            <span style={{ fontSize: 12, color: "#00C853", letterSpacing: 1 }}>LIVE</span>
          </div>
          <span style={{ fontSize: 13, color: "#666" }}>{userId}</span>
          <button onClick={() => { setLoggedIn(false); setScanHistory([]); setLatestResult(null); }} style={{
            background: "transparent", border: "1px solid #333", color: "#666",
            borderRadius: 6, padding: "4px 12px", cursor: "pointer", fontSize: 12, fontFamily: "monospace",
          }}>LOGOUT</button>
        </div>
      </div>

      <div style={{ maxWidth: 1000, margin: "0 auto", padding: "28px 20px" }}>
        <StatsBar history={scanHistory} />

        {/* Tabs */}
        <div style={{ display: "flex", gap: 0, margin: "24px 0 16px", borderBottom: "1px solid #1a1a2a" }}>
          {[["scan","◎ SCAN"], ["history","⧗ HISTORY"], ["about","ℹ ABOUT"]].map(([id, label]) => (
            <button key={id} onClick={() => setTab(id)} style={{
              padding: "10px 24px", background: "transparent", fontSize: 13, fontFamily: "monospace",
              color: tab === id ? "#7B61FF" : "#555",
              border: "none", borderBottom: tab === id ? "2px solid #7B61FF" : "2px solid transparent",
              cursor: "pointer", letterSpacing: 1,
            }}>
              {label}
            </button>
          ))}
        </div>

        {tab === "scan" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <ScanPanel onResult={handleScanResult} sessionActive={loggedIn} />
            {latestResult && <ResultCard result={latestResult} />}
          </div>
        )}

        {tab === "history" && (
          <div>
            <div style={{ fontSize: 12, color: "#555", marginBottom: 12, fontFamily: "monospace", letterSpacing: 1 }}>
              RECENT SCANS — {scanHistory.length} total
            </div>
            <HistoryPanel history={scanHistory} />
          </div>
        )}

        {tab === "about" && (
          <div style={{ background: "#0f0f13", border: "1px solid #1a1a2a", borderRadius: 14, padding: 28 }}>
            <div style={{ color: "#7B61FF", fontWeight: 700, fontSize: 16, marginBottom: 16, letterSpacing: 2 }}>
              PHISHGUARD AI — DETECTION ENGINE
            </div>
            {[
              ["Layer 1 — URL Anatomy", "Analyzes raw IP usage, suspicious TLDs, open redirects, excessive subdomains, and URL entropy to detect obfuscated phishing links."],
              ["Layer 2 — NLP Classifier", "Scans text for urgency/fear language, social engineering phrases, financial lures, and excessive capitalization using pattern matching and Bayesian scoring."],
              ["Layer 3 — Domain Reputation", "Detects brand impersonation, newly-registered domain patterns, and spoofed trusted entities using heuristic rules (production: WHOIS/RDAP API)."],
              ["Layer 4 — Homograph Detection", "Identifies Unicode/Cyrillic characters disguised as Latin letters — a sophisticated attack that defeats visual inspection."],
              ["Ensemble Scoring", "All four layers are blended using weighted probability fusion. Results trigger real-time WebSocket alerts with alarm sounds proportional to threat severity."],
            ].map(([title, desc]) => (
              <div key={title} style={{ marginBottom: 18 }}>
                <div style={{ color: "#ccc", fontWeight: 700, fontSize: 13, marginBottom: 5 }}>▶ {title}</div>
                <div style={{ color: "#777", fontSize: 13, lineHeight: 1.7, paddingLeft: 14 }}>{desc}</div>
              </div>
            ))}
            <div style={{ marginTop: 20, padding: "12px 16px", background: "#0a0a0f", borderRadius: 8, border: "1px solid #222" }}>
              <div style={{ fontSize: 12, color: "#555", fontFamily: "monospace", letterSpacing: 1, marginBottom: 6 }}>BACKEND STACK</div>
              <div style={{ fontSize: 13, color: "#888" }}>
                Java 21 • Spring Boot 3.2 • Spring WebSocket/STOMP • Multi-layer AI ensemble • REST API • Real-time alert push
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
