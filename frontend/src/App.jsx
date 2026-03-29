import { useState, useEffect, useRef } from "react";
import axios from "axios";
import CryptoJS from "crypto-js";
import "./App.css";

const API = "https://localhost:8443";
const FILE_AES_KEY_RAW = "ThisIsA32ByteSecretKey1234567890";

// ─── crypto helpers (unchanged) ───────────────────────────────────────────────
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
  return buf;
}
function bufferToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
async function generateSigningKeyPair() {
  return window.crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"]
  );
}
async function exportPublicKeyToPem(cryptoKey) {
  const spki = await window.crypto.subtle.exportKey("spki", cryptoKey);
  const b64  = bufferToBase64(spki);
  return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;
}
async function fileAesEncrypt(arrayBuffer) {
  const keyBytes  = new TextEncoder().encode(FILE_AES_KEY_RAW).slice(0, 32);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt"]);
  const iv        = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, cryptoKey, arrayBuffer);
  const combined  = new Uint8Array(16 + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 16);
  return btoa(String.fromCharCode(...combined));
}

// ─── Simulated packet data ────────────────────────────────────────────────────
function buildSecurePackets(message, encMsg, encKey, sig) {
  return [
    { layer: "TLS 1.3",    label: "Transport Layer Security",  color: "#16a34a", icon: "🔒", value: "Encrypted tunnel — payload invisible to network" },
    { layer: "HTTP/1.1",   label: "Application Layer",         color: "#2563eb", icon: "🌐", value: "POST /send  Authorization: Bearer eyJhbGci…[JWT]" },
    { layer: "AES-256-CBC",label: "Message Payload",           color: "#7c3aed", icon: "🔐", value: encMsg ? encMsg.slice(0, 64) + "…" : "Encrypting…" },
    { layer: "RSA-OAEP",   label: "Encrypted AES Key",         color: "#0d9488", icon: "🗝️", value: encKey ? encKey.slice(0, 64) + "…" : "Encrypting…" },
    { layer: "RSA-PSS",    label: "Digital Signature",         color: "#d97706", icon: "✍️", value: sig   ? sig.slice(0, 64)    + "…" : "Signing…"    },
  ];
}

function buildInsecurePackets(message, username) {
  return [
    { layer: "HTTP",       label: "No Transport Encryption ⚠️", color: "#dc2626", icon: "🔓", value: "Unencrypted HTTP — anyone on the network can read this!" },
    { layer: "HTTP/1.1",   label: "Application Layer",          color: "#dc2626", icon: "📡", value: `POST /send-plain  (NO Authorization header)` },
    { layer: "PLAINTEXT",  label: "Message Payload — EXPOSED",  color: "#dc2626", icon: "👁️", value: message ? `"${message}"` : "(your message will appear here in full)" },
    { layer: "IDENTITY",   label: "Sender — UNVERIFIED",        color: "#dc2626", icon: "🎭", value: username ? `username: "${username}"  (self-reported, no proof!)` : "anonymous" },
    { layer: "STORAGE",    label: "Stored on Server — PLAINTEXT",color:"#dc2626", icon: "💾", value: "insecure_messages.json — readable by anyone with file access" },
  ];
}

// ─── Packet Sniffer component ─────────────────────────────────────────────────
function PacketSniffer({ packets, mode }) {
  return (
    <div className={`sniffer ${mode === "secure" ? "sniffer--secure" : "sniffer--insecure"}`}>
      <div className="sniffer-header">
        <span className="sniffer-icon">{mode === "secure" ? "🛡️" : "🕵️"}</span>
        <span className="sniffer-title">
          {mode === "secure" ? "Network Packet View — Attacker Sees:" : "Network Packet View — Attacker Sees:"}
        </span>
        <span className={`sniffer-badge ${mode === "secure" ? "sniffer-badge--safe" : "sniffer-badge--danger"}`}>
          {mode === "secure" ? "PROTECTED" : "EXPOSED"}
        </span>
      </div>
      <div className="sniffer-packets">
        {packets.map((p, i) => (
          <div key={i} className="sniffer-packet" style={{ animationDelay: `${i * 80}ms` }}>
            <div className="sniffer-layer" style={{ background: p.color + "18", borderColor: p.color + "44", color: p.color }}>
              <span className="sniffer-layer-icon">{p.icon}</span>
              <span className="sniffer-layer-name">{p.layer}</span>
            </div>
            <div className="sniffer-packet-body">
              <span className="sniffer-packet-label">{p.label}</span>
              <span className={`sniffer-packet-value ${mode === "insecure" && p.layer === "PLAINTEXT" ? "sniffer-exposed" : ""}`}>
                {p.value}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Mode Toggle component ────────────────────────────────────────────────────
function ModeToggle({ mode, onChange }) {
  return (
    <div className="mode-toggle-wrap">
      <div className={`mode-toggle ${mode === "insecure" ? "mode-toggle--insecure" : ""}`}
           onClick={() => onChange(mode === "secure" ? "insecure" : "secure")}>
        <div className="mode-toggle-track">
          <span className="mode-toggle-label mode-toggle-label--left">🔒 SECURE</span>
          <div className={`mode-toggle-thumb ${mode === "insecure" ? "mode-toggle-thumb--right" : ""}`} />
          <span className="mode-toggle-label mode-toggle-label--right">⚠️ INSECURE</span>
        </div>
      </div>
      <p className="mode-toggle-hint">
        {mode === "secure"
          ? "Currently using AES-256-CBC + RSA-OAEP + RSA-PSS + JWT + TLS — toggle to see what happens without any of this"
          : "Currently sending PLAINTEXT over HTTP with NO authentication or encryption — toggle back to secure mode"}
      </p>
    </div>
  );
}

// ─── Comparison banner ────────────────────────────────────────────────────────
function ComparisonBanner({ mode }) {
  const rows = [
    { label: "Transport",    secure: "TLS 1.3 HTTPS",           insecure: "Plain HTTP — wiretappable" },
    { label: "Message",      secure: "AES-256-CBC encrypted",   insecure: "Plaintext — readable by anyone" },
    { label: "Key exchange", secure: "RSA-2048 OAEP",           insecure: "None" },
    { label: "Integrity",    secure: "RSA-PSS digital signature",insecure: "None — message can be tampered" },
    { label: "Auth",         secure: "JWT Bearer token",         insecure: "None — anyone can send" },
    { label: "Storage",      secure: "AES-256-GCM at rest",      insecure: "Plaintext on disk" },
  ];
  return (
    <div className="compare-banner">
      <div className="compare-header">
        <span className="compare-col compare-col--label"></span>
        <span className={`compare-col compare-col--secure ${mode === "secure" ? "compare-col--active" : ""}`}>🔒 Secure Mode</span>
        <span className={`compare-col compare-col--insecure ${mode === "insecure" ? "compare-col--active" : ""}`}>⚠️ Insecure Mode</span>
      </div>
      {rows.map((r, i) => (
        <div key={i} className="compare-row">
          <span className="compare-col compare-col--label">{r.label}</span>
          <span className={`compare-col compare-col--secure ${mode === "secure" ? "compare-col--active" : ""}`}>✅ {r.secure}</span>
          <span className={`compare-col compare-col--insecure ${mode === "insecure" ? "compare-col--active" : ""}`}>❌ {r.insecure}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView]             = useState("login");
  const [username, setUsername]     = useState("");
  const [password, setPassword]     = useState("");
  const [token, setToken]           = useState("");
  const tokenRef                    = useRef("");
  const [authError, setAuthError]   = useState("");

  // message state
  const [message, setMessage]                         = useState("");
  const [lastSentMessage, setLastSentMessage]         = useState("");
  const [messages, setMessages]                       = useState([]);
  const [insecureMessages, setInsecureMessages]       = useState([]);
  const [serverPublicKey, setServerPublicKey]         = useState("");
  const [encryptedMsg, setEncryptedMsg]               = useState("");
  const [encryptedKeyDisplay, setEncryptedKeyDisplay] = useState("");
  const [signatureDisplay, setSignatureDisplay]       = useState("");
  const [serverResponse, setServerResponse]           = useState("");
  const [sigStatus, setSigStatus]                     = useState("");
  const [sending, setSending]                         = useState(false);
  const signingKeysRef                                = useRef(null);

  // file state
  const [selectedFile, setSelectedFile]   = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStatus, setUploadStatus]   = useState("");
  const [uploading, setUploading]         = useState(false);
  const fileInputRef                      = useRef(null);

  // ui state
  const [tlsInfo, setTlsInfo]       = useState(null);
  const [activeTab, setActiveTab]   = useState("message");
  const [toasts, setToasts]         = useState([]);

  // ── NEW: mode toggle state ──
  const [mode, setMode]             = useState("secure"); // "secure" | "insecure"
  const [packets, setPackets]       = useState(() => buildSecurePackets("", "", "", ""));
  const [showComparison, setShowComparison] = useState(false);

  useEffect(() => {
    generateSigningKeyPair().then(kp => { signingKeysRef.current = kp; });
    axios.get(`${API}/public-key`).then(res => setServerPublicKey(res.data)).catch(() => {});
  }, []);

  // update live packet preview as message is typed
  useEffect(() => {
    if (mode === "secure") {
      setPackets(buildSecurePackets(message, encryptedMsg, encryptedKeyDisplay, signatureDisplay));
    } else {
      setPackets(buildInsecurePackets(message, username));
    }
  }, [mode, message, encryptedMsg, encryptedKeyDisplay, signatureDisplay, username]);

  const showToast = (msg, type = "success") => {
    const id = Date.now();
    setToasts(t => [...t, { id, msg, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 3200);
  };

  const handleModeChange = (newMode) => {
    setMode(newMode);
    setServerResponse("");
    setSigStatus("");
    setEncryptedMsg("");
    setEncryptedKeyDisplay("");
    setSignatureDisplay("");
    setLastSentMessage("");
    if (newMode === "insecure") {
      fetchInsecureMessages();
      showToast("⚠️ Switched to INSECURE mode — for demonstration only!", "error");
    } else {
      showToast("🔒 Switched back to SECURE mode", "success");
    }
  };

  // ── auth ──
  const handleRegister = async () => {
    setAuthError("");
    try {
      await axios.post(`${API}/register`, { username, password });
      showToast("Account created! Please log in.", "success");
      setView("login");
    } catch (err) { setAuthError(err.response?.data?.error || "Registration failed"); }
  };

  const handleLogin = async () => {
    setAuthError("");
    try {
      const res = await axios.post(`${API}/login`, { username, password });
      setToken(res.data.token);
      tokenRef.current = res.data.token;
      setView("app");
      fetchMessages(res.data.token);
      fetchTlsInfo();
    } catch (err) { setAuthError(err.response?.data?.error || "Login failed"); }
  };

  const handleLogout = () => {
    setToken(""); tokenRef.current = ""; setView("login");
    setUsername(""); setPassword(""); setMessages([]);
    setMode("secure");
  };

  const fetchMessages = async (jwt = tokenRef.current) => {
    try {
      const res = await axios.get(`${API}/messages`, { headers: { Authorization: `Bearer ${jwt}` } });
      setMessages(res.data);
    } catch (err) { console.error("Fetch messages failed:", err); }
  };

  const fetchInsecureMessages = async () => {
    try {
      const res = await axios.get(`${API}/messages-plain`);
      setInsecureMessages(res.data);
    } catch (err) { console.error("Fetch insecure messages failed:", err); }
  };

  // ── SECURE send (original) ──
  const sendSecureMessage = async () => {
    if (!message.trim() || sending) return;
    setSending(true); setSigStatus(""); setServerResponse("");
    try {
      const aesKey    = CryptoJS.lib.WordArray.random(32);
      const iv        = CryptoJS.lib.WordArray.random(16);
      const encrypted = CryptoJS.AES.encrypt(message, aesKey, { iv });
      const encryptedMessage = iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Base64);
      setEncryptedMsg(encryptedMessage);

      const importedKey = await window.crypto.subtle.importKey(
        "spki", pemToArrayBuffer(serverPublicKey),
        { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
      );
      const aesKeyBytes  = new TextEncoder().encode(aesKey.toString(CryptoJS.enc.Hex));
      const encKeyBuf    = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, importedKey, aesKeyBytes);
      const encryptedKey = bufferToBase64(encKeyBuf);
      setEncryptedKeyDisplay(encryptedKey);

      const msgBuf = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
      const sigBuf = await window.crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 }, signingKeysRef.current.privateKey, msgBuf
      );
      const signature        = bufferToBase64(sigBuf);
      const signingPublicKey = await exportPublicKeyToPem(signingKeysRef.current.publicKey);
      setSignatureDisplay(signature);

      const res = await axios.post(
        `${API}/send`,
        { encryptedMessage, encryptedKey, signature, signingPublicKey },
        { headers: { Authorization: `Bearer ${tokenRef.current}` } }
      );
      setServerResponse(res.data.status);
      setSigStatus("verified");
      setLastSentMessage(message);
      setMessage("");
      showToast("Message sent securely ✔", "success");
      await fetchMessages();
    } catch (err) {
      const msg = err.response?.data?.error || err.message;
      setServerResponse(`Error: ${msg}`);
      if (msg.includes("Signature")) setSigStatus("failed");
      showToast("Send failed: " + msg, "error");
    } finally { setSending(false); }
  };

  // ── INSECURE send (new) ──
  const sendInsecureMessage = async () => {
    if (!message.trim() || sending) return;
    setSending(true); setServerResponse("");
    try {
      const res = await axios.post(`${API}/send-plain`, { message, username });
      setServerResponse(res.data.status);
      setLastSentMessage(message);
      setMessage("");
      showToast("⚠️ Plaintext message sent (insecure!)", "error");
      await fetchInsecureMessages();
    } catch (err) {
      const msg = err.response?.data?.error || err.message;
      setServerResponse(`Error: ${msg}`);
      showToast("Send failed: " + msg, "error");
    } finally { setSending(false); }
  };

  const sendMessage = () => mode === "secure" ? sendSecureMessage() : sendInsecureMessage();

  // ── file upload (unchanged) ──
  const handleFileChange = e => setSelectedFile(e.target.files[0] || null);

  const handleUpload = async () => {
    if (!selectedFile || uploading) return;
    setUploading(true); setUploadProgress(10); setUploadStatus("Reading file…");
    try {
      const arrayBuf = await selectedFile.arrayBuffer();
      setUploadProgress(35); setUploadStatus("Encrypting with AES-256-CBC…");
      const encrypted = await fileAesEncrypt(arrayBuf);
      setUploadProgress(65); setUploadStatus("Uploading…");
      const formData = new FormData();
      formData.append("file", new Blob([encrypted], { type: "text/plain" }), selectedFile.name);
      formData.append("filename", selectedFile.name);
      const res = await axios.post(`${API}/upload`, formData, {
        headers: { Authorization: `Bearer ${tokenRef.current}` },
      });
      setUploadProgress(100); setUploadStatus(`✔ Saved as: ${res.data.savedAs}`);
      showToast("File encrypted and uploaded ✔", "success");
      setSelectedFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    } catch (err) {
      setUploadStatus("✘ " + (err.response?.data?.error || err.message));
      showToast("Upload failed", "error");
    } finally { setUploading(false); }
  };

  const fetchTlsInfo = async () => {
    try {
      const res = await axios.get(`${API}/secure`, { headers: { Authorization: `Bearer ${tokenRef.current}` } });
      setTlsInfo(res.data.tls);
    } catch { setTlsInfo(null); }
  };

  // ── auth screen ──
  if (view === "login" || view === "register") {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="auth-logo">
            <span className="auth-logo-icon">🔒</span>
            <span className="auth-logo-text">SecureVault</span>
          </div>
          <p className="auth-subtitle">AES-256 · RSA-2048 · TLS · JWT</p>
          <h2 className="auth-heading">{view === "login" ? "Sign In" : "Create Account"}</h2>
          <div className="field">
            <label className="field-label">Username</label>
            <input className="field-input" placeholder="Enter username" value={username}
              onChange={e => setUsername(e.target.value)} autoFocus />
          </div>
          <div className="field">
            <label className="field-label">Password {view === "register" && <span className="field-hint">(min 8 chars)</span>}</label>
            <input className="field-input" type="password" placeholder="Enter password" value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === "Enter" && (view === "login" ? handleLogin() : handleRegister())} />
          </div>
          {authError && <div className="auth-error">{authError}</div>}
          <button className="btn btn-primary btn-full" onClick={view === "login" ? handleLogin : handleRegister}>
            {view === "login" ? "Sign In →" : "Create Account →"}
          </button>
          <p className="auth-switch">
            {view === "login" ? "Don't have an account? " : "Already have an account? "}
            <button className="auth-switch-link"
              onClick={() => { setView(view === "login" ? "register" : "login"); setAuthError(""); }}>
              {view === "login" ? "Register" : "Sign In"}
            </button>
          </p>
        </div>
      </div>
    );
  }

  // ── main app ──
  return (
    <div className="app">
      {/* ── topbar ── */}
      <header className="topbar">
        <div className="topbar-left">
          <span className="topbar-logo">🔒 SecureVault</span>
          <span className={`tls-pill ${tlsInfo ? "tls-pill--secure" : "tls-pill--pending"}`}>
            <span className="tls-dot"></span>
            {tlsInfo ? `${tlsInfo.tlsVersion} · Secure` : "Checking TLS…"}
          </span>
        </div>
        <div className="topbar-right">
          <span className="topbar-user">👤 {username}</span>
          <button className="btn btn-ghost btn-sm" onClick={handleLogout}>Logout</button>
        </div>
      </header>

      {/* ── mode warning banner ── */}
      {mode === "insecure" && (
        <div className="insecure-banner">
          <span className="insecure-banner-icon">⚠️</span>
          <span className="insecure-banner-text">
            <strong>INSECURE MODE — Educational Demo Only.</strong> Messages are sent as plaintext with no encryption, no authentication, and no signature. This simulates how data exchange worked before modern cryptography.
          </span>
          <button className="insecure-banner-fix" onClick={() => handleModeChange("secure")}>
            Switch back to Secure →
          </button>
        </div>
      )}

      {/* ── hero ── */}
      <div className={`hero-strip ${mode === "insecure" ? "hero-strip--insecure" : ""}`}>
        <div className="hero-title">Secure Data Exchange System</div>
        <div className="hero-badges">
          {mode === "secure" ? (
            <>
             {["AES-256-CBC","RSA-2048 OAEP","RSA-PSS Signatures","JWT Auth","TLS 1.3"].map(b => (
    <span key={b} className="badge">{b}</span>
  ))}
            </>
          ) : (
            <>
              {["No Encryption","No Signature","No Auth","Plaintext HTTP"].map(b => (
    <span key={b} className="badge badge--danger">{b}</span>
  ))}
            </>
          )}
        </div>
      </div>

      {/* ── overview cards ── */}
      <div className="overview-grid">
        <div className="overview-card">
          <div className="overview-icon">🔐</div>
          <div className="overview-label">Message Encryption</div>
          <div className={`overview-value ${mode === "insecure" ? "text-red" : ""}`}>
            {mode === "secure" ? "AES-256-CBC + RSA-OAEP" : "❌ None — Plaintext"}
          </div>
        </div>
        <div className="overview-card">
          <div className="overview-icon">✍️</div>
          <div className="overview-label">Non-repudiation</div>
          <div className={`overview-value ${mode === "insecure" ? "text-red" : ""}`}>
            {mode === "secure" ? "RSA-PSS Digital Signature" : "❌ None — Spoofable"}
          </div>
        </div>
        <div className="overview-card">
          <div className="overview-icon">🪙</div>
          <div className="overview-label">Access Control</div>
          <div className={`overview-value ${mode === "insecure" ? "text-red" : ""}`}>
            {mode === "secure" ? "JWT Bearer Token (2h)" : "❌ None — Open Endpoint"}
          </div>
        </div>
        <div className="overview-card">
          <div className="overview-icon">🌐</div>
          <div className="overview-label">Transport</div>
          <div className={`overview-value ${mode === "insecure" ? "text-red" : ""}`}>
            {mode === "secure" ? (tlsInfo?.tlsVersion ?? "TLS 1.3") + " / HTTPS" : "❌ HTTP — Unencrypted"}
          </div>
        </div>
      </div>

      {/* ── tabs ── */}
      <div className="tabs">
        <button className={`tab ${activeTab === "message" ? "tab--active" : ""}`} onClick={() => setActiveTab("message")}>📩 Message</button>
        <button className={`tab ${activeTab === "compare" ? "tab--active" : ""}`} onClick={() => setActiveTab("compare")}>⚖️ Comparison</button>
        <button className={`tab ${activeTab === "file"    ? "tab--active" : ""}`} onClick={() => setActiveTab("file")}>📁 File Upload</button>
        <button className={`tab ${activeTab === "tls"     ? "tab--active" : ""}`} onClick={() => { setActiveTab("tls"); fetchTlsInfo(); }}>🔒 TLS & Certs</button>
      </div>

      <div className="tab-content">

        {/* ──────────── MESSAGE TAB ──────────── */}
        {activeTab === "message" && (
          <div>
            {/* Mode Toggle */}
            <ModeToggle mode={mode} onChange={handleModeChange} />

            <div className="two-col">
              {/* LEFT: Client panel */}
              <div className={`panel ${mode === "secure" ? "panel-client" : "panel-client--insecure"}`}>
                <div className="panel-header">
                  <span className="panel-icon">{mode === "secure" ? "🧑‍💻" : "🙈"}</span>
                  <div>
                    <div className="panel-title">Client Side</div>
                    <div className="panel-sub">
                      {mode === "secure" ? "Browser encrypts before sending" : "Browser sends plaintext with zero protection"}
                    </div>
                  </div>
                  <span className={`panel-tag ${mode === "secure" ? "panel-tag--blue" : "panel-tag--red"}`}>
                    {mode === "secure" ? "ENCRYPT" : "PLAINTEXT"}
                  </span>
                </div>

                <div className="field">
                  <label className="field-label">
                    {mode === "secure" ? "Plaintext Message" : "Message (will be sent as-is ⚠️)"}
                  </label>
                  <input className={`field-input ${mode === "insecure" ? "field-input--danger" : ""}`}
                    value={message} placeholder={mode === "secure" ? "Type your secret message…" : "Type a message — it will be fully visible on the network…"}
                    onChange={e => setMessage(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && sendMessage()} />
                </div>

                <button className={`btn btn-full ${mode === "secure" ? "btn-primary" : "btn-danger"}`}
                  onClick={sendMessage} disabled={sending}>
                  {sending
                    ? (mode === "secure" ? "Encrypting & Sending…" : "Sending plaintext…")
                    : (mode === "secure" ? "Send Securely 🔒" : "Send Without Encryption ⚠️")}
                </button>

                {sigStatus === "verified" && <div className="status-row status-row--success">✅ Signature verified by server</div>}
                {sigStatus === "failed"   && <div className="status-row status-row--error">❌ Signature verification FAILED</div>}

                {/* Crypto details — secure mode */}
                {mode === "secure" && (
                  <div className="crypto-details">
                    <div className="crypto-row"><span className="crypto-label">Original Message</span><span className="crypto-value">{lastSentMessage || <em>—</em>}</span></div>
                    <div className="crypto-row"><span className="crypto-label">AES-256-CBC Ciphertext</span><textarea className="crypto-textarea" readOnly rows={2} value={encryptedMsg} /></div>
                    <div className="crypto-row"><span className="crypto-label">RSA-OAEP Encrypted AES Key</span><textarea className="crypto-textarea" readOnly rows={2} value={encryptedKeyDisplay} /></div>
                    <div className="crypto-row"><span className="crypto-label">RSA-PSS Signature</span><textarea className="crypto-textarea" readOnly rows={2} value={signatureDisplay} /></div>
                  </div>
                )}

                {/* Exposure callout — insecure mode */}
                {mode === "insecure" && lastSentMessage && (
                  <div className="exposure-callout">
                    <div className="exposure-title">🕵️ What an attacker sees on the wire:</div>
                    <div className="exposure-message">"{lastSentMessage}"</div>
                    <div className="exposure-note">Complete message is visible. No key needed. No tools needed. Just a packet sniffer.</div>
                  </div>
                )}
              </div>

              {/* RIGHT: Server + Packet Sniffer */}
              <div className={`panel ${mode === "secure" ? "panel-server" : "panel-server--insecure"}`}>
                <div className="panel-header">
                  <span className="panel-icon">🖥️</span>
                  <div>
                    <div className="panel-title">Server Side</div>
                    <div className="panel-sub">
                      {mode === "secure" ? "Decrypted & stored securely" : "Receives & stores raw plaintext"}
                    </div>
                  </div>
                  <span className={`panel-tag ${mode === "secure" ? "panel-tag--green" : "panel-tag--red"}`}>
                    {mode === "secure" ? "DECRYPT" : "RAW"}
                  </span>
                </div>

                <div className="server-status">
                  <span className="server-status-label">Last Response</span>
                  <span className={`server-status-value ${serverResponse.startsWith("Error") ? "text-red" : mode === "insecure" ? "text-amber" : "text-green"}`}>
                    {serverResponse || "—"}
                  </span>
                </div>

                {/* Pipeline — only show in secure mode */}
                {mode === "secure" && (
                  <div className="pipeline-row">
                    {["Verify JWT","Verify RSA-PSS","RSA-OAEP decrypt","AES-CBC decrypt","AES-GCM store"].map((s, i, a) => (
                      <span key={s} style={{display:"flex",alignItems:"center",gap:"0.4rem"}}>
                        <div className="pipeline-step"><div className="pipeline-num">{i+1}</div><div className="pipeline-text">{s}</div></div>
                        {i < a.length-1 && <div className="pipeline-arrow">→</div>}
                      </span>
                    ))}
                  </div>
                )}

                {/* Insecure pipeline */}
                {mode === "insecure" && (
                  <div className="pipeline-row pipeline-row--insecure">
                    {["No auth check ❌","No signature check ❌","No decryption needed ❌","Save plaintext directly ❌"].map((s, i, a) => (
                      <span key={s} style={{display:"flex",alignItems:"center",gap:"0.4rem"}}>
                        <div className="pipeline-step"><div className="pipeline-num pipeline-num--red">{i+1}</div><div className="pipeline-text">{s}</div></div>
                        {i < a.length-1 && <div className="pipeline-arrow">→</div>}
                      </span>
                    ))}
                  </div>
                )}

                {/* Packet Sniffer */}
                <PacketSniffer packets={packets} mode={mode} />

                {/* Messages list */}
                <div className="messages-header">
                  <span className="messages-title">
                    {mode === "secure" ? "Decrypted Messages" : "⚠️ Plaintext Messages (stored unencrypted)"}
                  </span>
                  <button className="btn btn-ghost btn-sm"
                    onClick={() => mode === "secure" ? fetchMessages(tokenRef.current) : fetchInsecureMessages()}>
                    ↻ Refresh
                  </button>
                </div>

                {mode === "secure" && (
                  messages.length === 0
                    ? <p className="no-messages">No messages yet. Send one!</p>
                    : messages.map((m, i) => (
                      <div key={i} className="message-item">
                        <div className="message-meta">
                          <span>👤 {m.sender}</span>
                          <span>{new Date(m.timestamp).toLocaleDateString('en-GB')} {new Date(m.timestamp).toLocaleTimeString('en-GB')}</span>
                        </div>
                        <div className="message-text">🔓 {m.message}</div>
                      </div>
                    ))
                )}

                {mode === "insecure" && (
                  insecureMessages.length === 0
                    ? <p className="no-messages">No insecure messages sent yet.</p>
                    : insecureMessages.map((m, i) => (
                      <div key={i} className="message-item message-item--insecure">
                        <div className="message-meta">
                          <span>🎭 {m.sender} <span style={{color:"#dc2626",fontSize:"0.68rem"}}>(unverified)</span></span>
                          <span>{new Date(m.timestamp).toLocaleDateString('en-GB')} {new Date(m.timestamp).toLocaleTimeString('en-GB')}</span>
                        </div>
                        <div className="message-text" style={{color:"#dc2626"}}>
                          👁️ {m.message} <span style={{fontSize:"0.72rem",color:"#94a3b8"}}>(stored as plaintext)</span>
                        </div>
                      </div>
                    ))
                )}
              </div>
            </div>
          </div>
        )}

        {/* ──────────── COMPARISON TAB ──────────── */}
        {activeTab === "compare" && (
          <div className="single-col">
            <div className="panel">
              <div className="panel-header">
                <span className="panel-icon">⚖️</span>
                <div><div className="panel-title">Secure vs Insecure — Side by Side</div>
                  <div className="panel-sub">See exactly what changes between the two modes</div></div>
              </div>

              <ComparisonBanner mode={mode} />

              <div style={{ marginTop: "1.5rem" }}>
                <div className="compare-explainer-title">🎓 Why does this matter?</div>
                <div className="compare-explainer-grid">
                  <div className="compare-explainer-card compare-explainer-card--threat">
                    <div className="compare-explainer-card-title">🕵️ Man-in-the-Middle Attack</div>
                    <p>Without TLS, an attacker between you and the server can intercept, read, and even modify every message. They don't need to break any encryption — there is none.</p>
                    <div className="compare-explainer-card-verdict">Secure mode prevents this with TLS 1.3 + AES-256.</div>
                  </div>
                  <div className="compare-explainer-card compare-explainer-card--threat">
                    <div className="compare-explainer-card-title">🎭 Identity Spoofing</div>
                    <p>Without JWT auth and RSA-PSS signatures, anyone can send a message claiming to be you. There's no cryptographic proof of who sent a message.</p>
                    <div className="compare-explainer-card-verdict">Secure mode prevents this with RSA-PSS signatures + JWT.</div>
                  </div>
                  <div className="compare-explainer-card compare-explainer-card--threat">
                    <div className="compare-explainer-card-title">💾 Data Breach at Rest</div>
                    <p>If the server is breached in insecure mode, all stored messages are immediately readable as plain text. No extra steps needed by the attacker.</p>
                    <div className="compare-explainer-card-verdict">Secure mode prevents this with AES-256-GCM at rest.</div>
                  </div>
                  <div className="compare-explainer-card compare-explainer-card--threat">
                    <div className="compare-explainer-card-title">✏️ Message Tampering</div>
                    <p>Without RSA-PSS signatures, a message can be altered in transit and neither party can detect it. Integrity is completely broken.</p>
                    <div className="compare-explainer-card-verdict">Secure mode prevents this with RSA-PSS digital signature verification.</div>
                  </div>
                </div>
              </div>

              <div style={{ marginTop: "1.5rem" }}>
                <div className="compare-explainer-title">🔁 Try It Yourself</div>
                <div className="compare-try-steps">
                  {[
                    "Open the Message tab and type a message in Secure Mode — notice the ciphertext shown is unreadable gibberish",
                    "Toggle to Insecure Mode and send the same message — it appears in the packet sniffer in full plaintext",
                    "Check the server-side pipeline — secure mode runs 5 verification steps; insecure runs zero",
                    "In insecure mode, the messages are stored as plaintext in insecure_messages.json on the server",
                    "Toggle back and forth to see the real-time packet view change between protected and exposed",
                  ].map((s, i) => (
                    <div key={i} className="compare-try-step">
                      <span className="compare-try-num">{i + 1}</span>
                      <span>{s}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ marginTop: "1.5rem", textAlign: "center" }}>
                <ModeToggle mode={mode} onChange={handleModeChange} />
              </div>
            </div>
          </div>
        )}

        {/* ──────────── FILE TAB ──────────── */}
        {activeTab === "file" && (
          <div className="single-col">
            <div className="panel">
              <div className="panel-header">
                <span className="panel-icon">📁</span>
                <div><div className="panel-title">Encrypted File Upload</div><div className="panel-sub">File encrypted with AES-256-CBC in browser before upload</div></div>
                <span className="panel-tag panel-tag--blue">AES-256-CBC</span>
              </div>
              <div className="file-zone">
                <div className="file-zone-icon">⬆</div>
                <p className="file-zone-text">Select a file to encrypt and upload</p>
                <input ref={fileInputRef} type="file" className="file-input-native" id="fileInput" onChange={handleFileChange} />
                <label htmlFor="fileInput" className="btn btn-ghost" style={{cursor:"pointer"}}>Browse Files</label>
                {selectedFile && <div className="file-selected">📄 <strong>{selectedFile.name}</strong> ({(selectedFile.size/1024).toFixed(1)} KB)</div>}
              </div>
              {uploadProgress > 0 && (
                <div className="progress-row">
                  <div className="progress-bar"><div className="progress-fill" style={{ width: `${uploadProgress}%` }}></div></div>
                  <span className="progress-label">{uploadStatus}</span>
                </div>
              )}
              <button className="btn btn-primary btn-full" onClick={handleUpload} disabled={!selectedFile || uploading}>
                {uploading ? "Encrypting & Uploading…" : "Encrypt & Upload 🔒"}
              </button>
              <div className="how-it-works">
                <div className="how-title">How file encryption works</div>
                <div className="how-steps">
                  {["Random 16-byte IV generated in browser","File bytes encrypted with AES-256-CBC","IV prepended to ciphertext, Base64-encoded","Sent over TLS — double encrypted in transit","Server slices IV, decrypts, saves to uploads/"].map((s,i) => (
                    <div key={i} className="how-step"><span className="how-num">{i+1}</span>{s}</div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ──────────── TLS TAB ──────────── */}
        {activeTab === "tls" && (
          <div className="single-col">
            <div className="panel">
              <div className="panel-header">
                <span className="panel-icon">🔒</span>
                <div><div className="panel-title">TLS Connection & PKI</div><div className="panel-sub">Certificate-based authentication details</div></div>
                <button className="btn btn-ghost btn-sm" onClick={fetchTlsInfo}>↻ Refresh</button>
              </div>
              {!tlsInfo ? <p className="no-messages">Click Refresh to load TLS info.</p> : (
                <div className="cert-grid">
                  <div className="cert-section-title">🌐 TLS Session</div>
                  <div className="cert-row"><span className="cert-key">Protocol</span><span className="cert-val mono">{tlsInfo.tlsVersion}</span></div>
                  <div className="cert-row"><span className="cert-key">Cipher Suite</span><span className="cert-val mono">{tlsInfo.cipher}</span></div>
                  <div className="cert-row"><span className="cert-key">Server Cert Subject</span><span className="cert-val mono">{tlsInfo.serverCert?.subject}</span></div>
                  <div className="cert-row"><span className="cert-key">Server Cert Issuer</span><span className="cert-val mono">{tlsInfo.serverCert?.issuer}</span></div>
                  <div className="cert-section-title" style={{marginTop:"1.2rem"}}>🪪 Client Certificate</div>
                  {tlsInfo.clientCert
                    ? <>
                        <div className="cert-row"><span className="cert-key">Common Name (CN)</span><span className="cert-val mono">{tlsInfo.clientCert.cn}</span></div>
                        <div className="cert-row"><span className="cert-key">Organisation</span><span className="cert-val mono">{tlsInfo.clientCert.org}</span></div>
                        <div className="cert-row"><span className="cert-key">Issuer</span><span className="cert-val mono">{tlsInfo.clientCert.issuer}</span></div>
                        <div className="cert-row"><span className="cert-key">Serial Number</span><span className="cert-val mono">{tlsInfo.clientCert.serial}</span></div>
                        <div className="cert-row"><span className="cert-key">CA Authorized</span><span className={`cert-val ${tlsInfo.authorized ? "text-green" : "text-amber"}`}>{tlsInfo.authorized ? "✔ Yes" : "⚠ Not CA-verified"}</span></div>
                      </>
                    : <div className="cert-row"><span className="cert-key">Status</span><span className="cert-val text-amber">⚠ No client certificate presented</span></div>
                  }
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="toast-stack">
        {toasts.map(t => <div key={t.id} className={`toast toast--${t.type}`}>{t.msg}</div>)}
      </div>

      <footer className="footer">
        SecureVault · Secure Data Exchange Using Cryptographic Techniques · AES-256 + RSA-2048 + TLS
      </footer>
    </div>
  );
}
