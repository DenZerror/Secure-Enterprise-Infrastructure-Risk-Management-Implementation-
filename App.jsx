import { useState, useEffect, useRef } from "react";
import axios from "axios";
import CryptoJS from "crypto-js";
import "./App.css";

const API = "https://localhost:8443";
// AES key for file encryption — must match backend FILE_AES_KEY
const FILE_AES_KEY_RAW = "ThisIsA32ByteSecretKey1234567890";

// ─── CRYPTO HELPERS ───────────────────────────────────────────

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

// Web Crypto AES-CBC for file encryption
async function fileAesEncrypt(arrayBuffer) {
  const keyBytes = new TextEncoder().encode(FILE_AES_KEY_RAW).slice(0, 32);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, cryptoKey, arrayBuffer);
  const combined = new Uint8Array(16 + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 16);
  return btoa(String.fromCharCode(...combined));
}

// ─── APP ──────────────────────────────────────────────────────

export default function App() {
  // Auth
  const [view, setView]           = useState("login");
  const [username, setUsername]   = useState("");
  const [password, setPassword]   = useState("");
  const [token, setToken]         = useState("");
  const tokenRef                  = useRef("");
  const [authError, setAuthError] = useState("");

  // Messaging
  const [message, setMessage]                   = useState("");
  const [lastSentMessage, setLastSentMessage]   = useState("");
  const [messages, setMessages]                 = useState([]);
  const [serverPublicKey, setServerPublicKey]   = useState("");
  const [encryptedMsg, setEncryptedMsg]         = useState("");
  const [encryptedKeyDisplay, setEncryptedKeyDisplay] = useState("");
  const [signatureDisplay, setSignatureDisplay] = useState("");
  const [serverResponse, setServerResponse]     = useState("");
  const [sigStatus, setSigStatus]               = useState("");
  const [sending, setSending]                   = useState(false);
  const signingKeysRef                          = useRef(null);

  // File upload
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStatus, setUploadStatus]     = useState("");
  const [uploading, setUploading]           = useState(false);
  const fileInputRef = useRef(null);

  // TLS / Security
  const [tlsInfo, setTlsInfo]     = useState(null);
  const [activeTab, setActiveTab] = useState("message"); // message | file | tls

  // Toast notifications
  const [toasts, setToasts] = useState([]);

  // ── Init ──
  useEffect(() => {
    generateSigningKeyPair().then(kp => { signingKeysRef.current = kp; });
    axios.get(`${API}/public-key`).then(res => setServerPublicKey(res.data)).catch(() => {});
  }, []);

  // ── Toast helper ──
  const showToast = (msg, type = "success") => {
    const id = Date.now();
    setToasts(t => [...t, { id, msg, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 3200);
  };

  // ── Auth ──
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
  };

  // ── Messages ──
  const fetchMessages = async (jwt = tokenRef.current) => {
    try {
      const res = await axios.get(`${API}/messages`, { headers: { Authorization: `Bearer ${jwt}` } });
      setMessages(res.data);
    } catch (err) { console.error("Fetch messages failed:", err); }
  };

  const sendMessage = async () => {
    if (!message.trim() || sending) return;
    setSending(true); setSigStatus(""); setServerResponse("");
    try {
      // AES-256-CBC encrypt with random key+IV (via CryptoJS)
      const aesKey = CryptoJS.lib.WordArray.random(32);
      const iv     = CryptoJS.lib.WordArray.random(16);
      const encrypted = CryptoJS.AES.encrypt(message, aesKey, { iv });
      const encryptedMessage = iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Base64);
      setEncryptedMsg(encryptedMessage);

      // RSA-OAEP encrypt AES key
      const importedKey = await window.crypto.subtle.importKey(
        "spki", pemToArrayBuffer(serverPublicKey),
        { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
      );
      const aesKeyBytes = new TextEncoder().encode(aesKey.toString(CryptoJS.enc.Hex));
      const encKeyBuf   = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, importedKey, aesKeyBytes);
      const encryptedKey = bufferToBase64(encKeyBuf);
      setEncryptedKeyDisplay(encryptedKey);

      // RSA-PSS sign the encrypted message
      const msgBuf = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));
      const sigBuf = await window.crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 }, signingKeysRef.current.privateKey, msgBuf
      );
      const signature      = bufferToBase64(sigBuf);
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

  // ── File Upload ──
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

  // ── TLS Info ──
  const fetchTlsInfo = async () => {
    try {
      const res = await axios.get(`${API}/secure`, { headers: { Authorization: `Bearer ${tokenRef.current}` } });
      setTlsInfo(res.data.tls);
    } catch { setTlsInfo(null); }
  };

  // ─────────────────────────────────────────────────────────────
  // RENDER — AUTH SCREENS
  // ─────────────────────────────────────────────────────────────
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

  // ─────────────────────────────────────────────────────────────
  // RENDER — MAIN APP
  // ─────────────────────────────────────────────────────────────
  return (
    <div className="app">

      {/* ── HEADER ── */}
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

      {/* ── HERO STRIP ── */}
      <div className="hero-strip">
        <div className="hero-title">Secure Data Exchange System</div>
        <div className="hero-badges">
          <span className="badge badge-blue">AES-256-CBC</span>
          <span className="badge badge-indigo">RSA-2048 OAEP</span>
          <span className="badge badge-violet">RSA-PSS Signatures</span>
          <span className="badge badge-green">JWT Auth</span>
          <span className="badge badge-teal">TLS 1.3</span>
        </div>
      </div>

      {/* ── SECURITY OVERVIEW CARDS ── */}
      <div className="overview-grid">
        <div className="overview-card">
          <div className="overview-icon">🔐</div>
          <div className="overview-label">Message Encryption</div>
          <div className="overview-value">AES-256-CBC + RSA-OAEP</div>
        </div>
        <div className="overview-card">
          <div className="overview-icon">✍️</div>
          <div className="overview-label">Non-repudiation</div>
          <div className="overview-value">RSA-PSS Digital Signature</div>
        </div>
        <div className="overview-card">
          <div className="overview-icon">🪙</div>
          <div className="overview-label">Access Control</div>
          <div className="overview-value">JWT Bearer Token (2h)</div>
        </div>
        <div className="overview-card">
          <div className="overview-icon">🌐</div>
          <div className="overview-label">Transport</div>
          <div className="overview-value">{tlsInfo?.tlsVersion ?? "TLS 1.3"} / HTTPS</div>
        </div>
      </div>

      {/* ── TABS ── */}
      <div className="tabs">
        <button className={`tab ${activeTab === "message" ? "tab--active" : ""}`} onClick={() => setActiveTab("message")}>
          📩 Secure Message
        </button>
        <button className={`tab ${activeTab === "file" ? "tab--active" : ""}`} onClick={() => setActiveTab("file")}>
          📁 File Upload
        </button>
        <button className={`tab ${activeTab === "tls" ? "tab--active" : ""}`} onClick={() => { setActiveTab("tls"); fetchTlsInfo(); }}>
          🔒 TLS & Certs
        </button>
      </div>

      <div className="tab-content">

        {/* ══ TAB: MESSAGE ══ */}
        {activeTab === "message" && (
          <div className="two-col">

            {/* Client side */}
            <div className="panel panel-client">
              <div className="panel-header">
                <span className="panel-icon">🧑‍💻</span>
                <div>
                  <div className="panel-title">Client Side</div>
                  <div className="panel-sub">Browser encrypts before sending</div>
                </div>
                <span className="panel-tag panel-tag--blue">ENCRYPT</span>
              </div>

              <div className="field">
                <label className="field-label">Plaintext Message</label>
                <input className="field-input" value={message}
                  placeholder="Type your secret message…"
                  onChange={e => setMessage(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && sendMessage()} />
              </div>

              <button className="btn btn-primary btn-full" onClick={sendMessage} disabled={sending}>
                {sending ? "Encrypting & Sending…" : "Send Securely 🔒"}
              </button>

              {sigStatus === "verified" && (
                <div className="status-row status-row--success">✅ Signature verified by server</div>
              )}
              {sigStatus === "failed" && (
                <div className="status-row status-row--error">❌ Signature verification FAILED</div>
              )}

              <div className="crypto-details">
                <div className="crypto-row">
                  <span className="crypto-label">Original Message</span>
                  <span className="crypto-value">{lastSentMessage || <em>—</em>}</span>
                </div>
                <div className="crypto-row">
                  <span className="crypto-label">AES-256-CBC Ciphertext</span>
                  <textarea className="crypto-textarea" readOnly rows={2} value={encryptedMsg} />
                </div>
                <div className="crypto-row">
                  <span className="crypto-label">RSA-OAEP Encrypted AES Key</span>
                  <textarea className="crypto-textarea" readOnly rows={2} value={encryptedKeyDisplay} />
                </div>
                <div className="crypto-row">
                  <span className="crypto-label">RSA-PSS Signature</span>
                  <textarea className="crypto-textarea" readOnly rows={2} value={signatureDisplay} />
                </div>
              </div>
            </div>

            {/* Server side */}
            <div className="panel panel-server">
              <div className="panel-header">
                <span className="panel-icon">🖥️</span>
                <div>
                  <div className="panel-title">Server Side</div>
                  <div className="panel-sub">Decrypted & stored securely</div>
                </div>
                <span className="panel-tag panel-tag--green">DECRYPT</span>
              </div>

              <div className="server-status">
                <span className="server-status-label">Last Response</span>
                <span className={`server-status-value ${serverResponse.startsWith("Error") ? "text-red" : "text-green"}`}>
                  {serverResponse || "—"}
                </span>
              </div>

              <div className="pipeline-row">
                <div className="pipeline-step">
                  <div className="pipeline-num">1</div>
                  <div className="pipeline-text">Verify JWT token</div>
                </div>
                <div className="pipeline-arrow">→</div>
                <div className="pipeline-step">
                  <div className="pipeline-num">2</div>
                  <div className="pipeline-text">Verify RSA-PSS sig</div>
                </div>
                <div className="pipeline-arrow">→</div>
                <div className="pipeline-step">
                  <div className="pipeline-num">3</div>
                  <div className="pipeline-text">RSA-OAEP decrypt key</div>
                </div>
                <div className="pipeline-arrow">→</div>
                <div className="pipeline-step">
                  <div className="pipeline-num">4</div>
                  <div className="pipeline-text">AES-CBC decrypt msg</div>
                </div>
                <div className="pipeline-arrow">→</div>
                <div className="pipeline-step">
                  <div className="pipeline-num">5</div>
                  <div className="pipeline-text">AES-GCM store to disk</div>
                </div>
              </div>

              <div className="messages-header">
                <span className="messages-title">Decrypted Messages</span>
                <button className="btn btn-ghost btn-sm" onClick={() => fetchMessages()}>↻ Refresh</button>
              </div>

              {messages.length === 0
                ? <p className="no-messages">No messages yet. Send one!</p>
                : messages.map((m, i) => (
                  <div key={i} className="message-item">
                    <div className="message-meta">
                      <span>👤 {m.sender}</span>
                      <span>{new Date(m.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="message-text">🔓 {m.message}</div>
                  </div>
                ))
              }
            </div>
          </div>
        )}

        {/* ══ TAB: FILE UPLOAD ══ */}
        {activeTab === "file" && (
          <div className="single-col">
            <div className="panel">
              <div className="panel-header">
                <span className="panel-icon">📁</span>
                <div>
                  <div className="panel-title">Encrypted File Upload</div>
                  <div className="panel-sub">File encrypted with AES-256-CBC in browser before upload</div>
                </div>
                <span className="panel-tag panel-tag--blue">AES-256-CBC</span>
              </div>

              <div className="file-zone">
                <div className="file-zone-icon">⬆</div>
                <p className="file-zone-text">Select a file to encrypt and upload</p>
                <input ref={fileInputRef} type="file" className="file-input-native"
                  id="fileInput" onChange={handleFileChange} />
                <label htmlFor="fileInput" className="btn btn-ghost" style={{cursor:"pointer"}}>
                  Browse Files
                </label>
                {selectedFile && (
                  <div className="file-selected">
                    📄 <strong>{selectedFile.name}</strong> ({(selectedFile.size/1024).toFixed(1)} KB)
                  </div>
                )}
              </div>

              {uploadProgress > 0 && (
                <div className="progress-row">
                  <div className="progress-bar">
                    <div className="progress-fill" style={{ width: `${uploadProgress}%` }}></div>
                  </div>
                  <span className="progress-label">{uploadStatus}</span>
                </div>
              )}

              <button className="btn btn-primary btn-full" onClick={handleUpload}
                disabled={!selectedFile || uploading}>
                {uploading ? "Encrypting & Uploading…" : "Encrypt & Upload 🔒"}
              </button>

              <div className="how-it-works">
                <div className="how-title">How file encryption works</div>
                <div className="how-steps">
                  <div className="how-step"><span className="how-num">1</span>Random 16-byte IV generated in browser</div>
                  <div className="how-step"><span className="how-num">2</span>File bytes encrypted with AES-256-CBC</div>
                  <div className="how-step"><span className="how-num">3</span>IV prepended to ciphertext, Base64-encoded</div>
                  <div className="how-step"><span className="how-num">4</span>Sent over TLS — double encrypted in transit</div>
                  <div className="how-step"><span className="how-num">5</span>Server slices IV, decrypts, saves to uploads/</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══ TAB: TLS & CERTS ══ */}
        {activeTab === "tls" && (
          <div className="single-col">
            <div className="panel">
              <div className="panel-header">
                <span className="panel-icon">🔒</span>
                <div>
                  <div className="panel-title">TLS Connection & PKI</div>
                  <div className="panel-sub">Certificate-based authentication details</div>
                </div>
                <button className="btn btn-ghost btn-sm" onClick={fetchTlsInfo}>↻ Refresh</button>
              </div>

              {!tlsInfo
                ? <p className="no-messages">Click Refresh to load TLS info.</p>
                : (
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
                          <div className="cert-row">
                            <span className="cert-key">CA Authorized</span>
                            <span className={`cert-val ${tlsInfo.authorized ? "text-green" : "text-amber"}`}>
                              {tlsInfo.authorized ? "✔ Yes" : "⚠ Not CA-verified"}
                            </span>
                          </div>
                        </>
                      : <div className="cert-row"><span className="cert-key">Status</span><span className="cert-val text-amber">⚠ No client certificate presented</span></div>
                    }
                  </div>
                )
              }
            </div>
          </div>
        )}

      </div>

      {/* ── TOASTS ── */}
      <div className="toast-stack">
        {toasts.map(t => (
          <div key={t.id} className={`toast toast--${t.type}`}>{t.msg}</div>
        ))}
      </div>

      <footer className="footer">
        SecureVault · Secure Data Exchange Using Cryptographic Techniques · AES-256 + RSA-2048 + TLS
      </footer>
    </div>
  );
}
