import { useState, useEffect } from "react";
import axios from "axios";
import CryptoJS from "crypto-js";

function App() {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);
  const [publicKey, setPublicKey] = useState("");
  const [encryptedMsg, setEncryptedMsg] = useState("");
  const [encryptedKeyState, setEncryptedKeyState] = useState("");
  const [serverResponse, setServerResponse] = useState("");

  // 🔑 Fetch server public key
  useEffect(() => {
    axios.get("https://localhost:8443/public-key")
      .then(res => setPublicKey(res.data))
      .catch(err => console.error(err));

    fetchMessages();
  }, []);

  // 📥 Fetch messages (already decrypted by server)
  const fetchMessages = async () => {
    try {
      const res = await axios.get("https://localhost:8443/messages");
      setMessages(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  // 🔐 Generate random AES key
  const generateAESKey = () => {
    return CryptoJS.lib.WordArray.random(32);
  };

  // 🔄 Convert PEM → ArrayBuffer (for RSA)
  const pemToArrayBuffer = (pem) => {
    const b64 = pem.replace(/-----.*-----/g, "").replace(/\n/g, "");
    const binary = atob(b64);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);

    for (let i = 0; i < binary.length; i++) {
      view[i] = binary.charCodeAt(i);
    }

    return buffer;
  };

  // 🚀 Send message (Hybrid Encryption)
  const sendMessage = async () => {
  try {
    const aesKey = generateAESKey();
    const iv = CryptoJS.lib.WordArray.random(16);

    const encrypted = CryptoJS.AES.encrypt(message, aesKey, { iv });

    const encryptedMessage = iv.concat(encrypted.ciphertext)
      .toString(CryptoJS.enc.Base64);

    setEncryptedMsg(encryptedMessage); // 👈 SHOW IN UI

    const cryptoKey = await window.crypto.subtle.importKey(
      "spki",
      pemToArrayBuffer(publicKey),
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      false,
      ["encrypt"]
    );

    const aesKeyBytes = new TextEncoder().encode(
      aesKey.toString(CryptoJS.enc.Hex)
    );

    const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      cryptoKey,
      aesKeyBytes
    );

    const encryptedKey = btoa(
      String.fromCharCode(...new Uint8Array(encryptedKeyBuffer))
    );

    setEncryptedKeyState(encryptedKey); // 👈 SHOW IN UI

    const res = await axios.post("https://localhost:8443/send", {
      encryptedMessage,
      encryptedKey
    });

    setServerResponse(res.data.status);

    setMessage("");

  } catch (err) {
    console.error(err);
  }

  await fetchMessages();
};

  return (
  <div style={{ padding: "20px", fontFamily: "Arial" }}>
    
    <h2>🔐 Secure Client-Server Communication</h2>

    {/* INPUT SECTION */}
    <input
      value={message}
      onChange={(e) => setMessage(e.target.value)}
      placeholder="Enter message"
      style={{ padding: "8px", marginRight: "10px" }}
    />

    <button onClick={sendMessage}>
      Send Securely
    </button>

    <hr />

    {/* CLIENT SIDE */}
    <div style={{ border: "2px solid blue", padding: "10px", marginBottom: "20px" }}>
      <h3>🧑‍💻 Client Side</h3>

      <p><b>Original Message:</b> {message}</p>

      <p><b>AES Encrypted Message:</b></p>
      <textarea value={encryptedMsg} readOnly rows={3} style={{ width: "100%" }} />

      <p><b>RSA Encrypted Key:</b></p>
      <textarea value={encryptedKeyState} readOnly rows={3} style={{ width: "100%" }} />
    </div>

    {/* TRANSFER */}
    <div style={{ textAlign: "center", margin: "20px 0" }}>
      <h3>⬇️ Secure Transfer via TLS ⬇️</h3>
    </div>

    {/* SERVER SIDE */}
    <div style={{ border: "2px solid green", padding: "10px" }}>
      <h3>🖥️ Server Side</h3>

      <p><b>Status:</b> {serverResponse}</p>

      <h4>Decrypted Messages:</h4>
      {messages.map((m, i) => (
        <p key={i}>🔓 {m}</p>
      ))}
    </div>

  </div>
);
}

export default App;