/* app.js */
/* global sodium, argon2 */

"use strict";
(async () => {
  try {
    await sodium.ready;
    console.log("libsodium ready ✅");
  } catch (e) {
    console.error("libsodium load failed ❌", e);
  }
  if (typeof argon2 === "undefined") {
    console.error("Argon2 not loaded ❌");
  } else {
    console.log("Argon2 ready ✅");
  }
})();
/************************************************************
 * Utility helpers
 ************************************************************/

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function utf8ToBytes(str) {
  return textEncoder.encode(str);
}

function bytesToUtf8(bytes) {
  return textDecoder.decode(bytes);
}

function toBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function randomBytes(length) {
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return arr;
}

// Best-effort zeroing of sensitive Uint8Arrays
function zeroBytes(bytes) {
  if (bytes && typeof bytes.fill === "function") {
    bytes.fill(0);
  }
}

// HKDF-style key separation using HMAC-SHA-256 via WebCrypto
async function deriveSubkey(masterKeyBytes, label) {
  const key = await crypto.subtle.importKey(
    "raw",
    masterKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const data = utf8ToBytes(label);
  const sig = await crypto.subtle.sign("HMAC", key, data);
  const subkey = new Uint8Array(sig).slice(0, 32); // 256-bit subkey
  return subkey;
}

/************************************************************
 * Argon2id KDF: password -> masterKey (used only for KDF)
 * Params:
 *  - parallelism: 4
 *  - memory: 256 MB (mem: 256 * 1024 KiB)
 *  - iterations: 3
 ************************************************************/

async function deriveMasterKeyArgon2id(password, salt) {
  const passwordStr = String(password); // argon2-browser expects string/Buffer
  const result = await argon2.hash({
    pass: passwordStr,
    salt,
    time: 3, // iterations
    mem: 256 * 1024, // KiB = 256 MB
    parallelism: 4,
    hashLen: 32, // 256-bit master key
    type: argon2.ArgonType.Argon2id
  });
  return result.hash; // Uint8Array
}

/************************************************************
 * XChaCha20-Poly1305 AEAD encryption/decryption
 * Using libsodium-wrappers-sumo
 ************************************************************/

async function encryptBytesXChaCha(plaintextBytes, password) {
  await sodium.ready;

  const salt = randomBytes(16); // for Argon2id
  const nonce = randomBytes(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  ); // 24 bytes

  const masterKey = await deriveMasterKeyArgon2id(password, salt);

  // Key separation (HKDF/HMAC-based)
  const encKey = await deriveSubkey(masterKey, "enc:xchacha20-poly1305:v1");
  const authKey = await deriveSubkey(
    masterKey,
    "auth:associated-data:v1"
  ); // reserved for future AD/MAC expansion
  const sessionKey = await deriveSubkey(
    masterKey,
    "session:ephemeral:v1"
  ); // reserved for messaging / forward secrecy

  // Associated Data: bind header fields cryptographically
  const headerAD = utf8ToBytes(
    "v1|XChaCha20-Poly1305|" + toBase64(salt) + "|" + toBase64(nonce)
  );

  const ciphertextWithTag = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintextBytes,
    headerAD,
    null, // no secret nonce
    nonce,
    encKey
  );

  const tagLen = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES; // 16 bytes
  const ciphertext = ciphertextWithTag.slice(
    0,
    ciphertextWithTag.length - tagLen
  );
  const tag = ciphertextWithTag.slice(ciphertextWithTag.length - tagLen);

  // Zero in-memory keys ASAP (best effort)
  zeroBytes(masterKey);
  zeroBytes(authKey);
  zeroBytes(sessionKey);

  const json = {
    version: 1,
    algorithm: "XChaCha20-Poly1305",
    kdf: {
      algorithm: "argon2id",
      params: {
        iterations: 3,
        memoryMB: 256,
        parallelism: 4,
        hashLen: 32
      }
    },
    nonce: toBase64(nonce),
    salt: toBase64(salt),
    ciphertext: toBase64(ciphertext),
    tag: toBase64(tag)
  };

  return json;
}

async function decryptBytesXChaCha(json, password) {
  await sodium.ready;

  if (!json || json.algorithm !== "XChaCha20-Poly1305" || json.version !== 1) {
    throw new Error("Unsupported format or algorithm");
  }

  const nonce = fromBase64(json.nonce);
  const salt = fromBase64(json.salt);
  const ciphertext = fromBase64(json.ciphertext);
  const tag = fromBase64(json.tag);

  const masterKey = await deriveMasterKeyArgon2id(password, salt);
  const encKey = await deriveSubkey(masterKey, "enc:xchacha20-poly1305:v1");
  const authKey = await deriveSubkey(masterKey, "auth:associated-data:v1");
  const sessionKey = await deriveSubkey(masterKey, "session:ephemeral:v1");

  const headerAD = utf8ToBytes(
    "v1|XChaCha20-Poly1305|" + toBase64(salt) + "|" + toBase64(nonce)
  );

  const fullCiphertext = new Uint8Array(ciphertext.length + tag.length);
  fullCiphertext.set(ciphertext, 0);
  fullCiphertext.set(tag, ciphertext.length);

  let plaintext;
  try {
    plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fullCiphertext,
      headerAD,
      nonce,
      encKey
    );
  } catch (e) {
    zeroBytes(masterKey);
    zeroBytes(encKey);
    zeroBytes(authKey);
    zeroBytes(sessionKey);
    throw new Error(
      "Decryption failed (wrong password or data has been tampered with)"
    );
  }

  zeroBytes(masterKey);
  zeroBytes(encKey);
  zeroBytes(authKey);
  zeroBytes(sessionKey);

  return plaintext;
}

/************************************************************
 * Password strength indicator (simple heuristic)
 ************************************************************/

function estimatePasswordStrength(pass) {
  let score = 0;
  if (!pass) return 0;
  if (pass.length >= 8) score += 1;
  if (pass.length >= 12) score += 1;
  if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) score += 1;
  if (/\d/.test(pass)) score += 1;
  if (/[^A-Za-z0-9]/.test(pass)) score += 1;
  return Math.min(score, 5);
}

function updatePasswordStrengthUI() {
  const passwordInput = document.getElementById("password");
  const pass = passwordInput.value;
  const score = estimatePasswordStrength(pass);
  const barInner = document.getElementById("password-bar-inner");
  const label = document.getElementById("password-strength-label");

  const perc = (score / 5) * 100;
  barInner.style.width = String(perc) + "%";

  let text = "Strength: ";
  let color = "#4b5563";
  if (score <= 1) {
    text += "Very Weak";
    color = "#f97373";
  } else if (score === 2) {
    text += "Weak";
    color = "#fb923c";
  } else if (score === 3) {
    text += "Medium";
    color = "#facc15";
  } else if (score === 4) {
    text += "Strong";
    color = "#4ade80";
  } else if (score === 5) {
    text += "Very Strong";
    color = "#22c55e";
  }

  barInner.style.backgroundColor = color;
  label.textContent = text;
}

/************************************************************
 * Clipboard handling (best-effort auto-clear after 10s)
 ************************************************************/

async function secureCopyToClipboard(text, statusElement) {
  if (!navigator.clipboard) {
    statusElement.textContent = "Clipboard API not available in this browser.";
    statusElement.className = "status error";
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    statusElement.textContent =
      "Encrypted JSON copied to clipboard. It will be cleared in ~10 seconds (best effort).";
    statusElement.className = "status ok";

    setTimeout(async () => {
      try {
        await navigator.clipboard.writeText("");
      } catch (e) {
        // best effort only
      }
    }, 10000);
  } catch (e) {
    statusElement.textContent = "Failed to copy to clipboard: " + e.message;
    statusElement.className = "status error";
  }
}

/************************************************************
 * Security Self Tests
 * - Nonce reuse
 * - Tampering detection
 * - Wrong password behavior
 * - RNG sanity
 ************************************************************/

const testOutputEl = document.getElementById("test-output");

function logTest(line) {
  testOutputEl.textContent += line + "\n";
}

function resetTests() {
  testOutputEl.textContent = "";
}

async function runSelfTests() {
  resetTests();
  logTest("Running self tests…");

  const testPassword = "TestPassword123!@#";
  const testPlaintext = utf8ToBytes("This is a test message.");

  // 1. Nonce reuse check
  logTest("[1] Testing for nonce reuse…");
  const nonceSet = new Set();
  const iterations = 25;
  for (let i = 0; i < iterations; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const json = await encryptBytesXChaCha(testPlaintext, testPassword);
    if (nonceSet.has(json.nonce)) {
      logTest("❌ Nonce reuse detected!");
      zeroBytes(testPlaintext);
      return;
    }
    nonceSet.add(json.nonce);
  }
  logTest("✅ No nonce reuse observed across " + iterations + " encryptions.");

  // 2. Tampering detection
  logTest("[2] Testing tampering detection…");
  const json2 = await encryptBytesXChaCha(testPlaintext, testPassword);
  const ctBytes = fromBase64(json2.ciphertext);
  if (ctBytes.length > 0) {
    ctBytes[0] ^= 0xff; // flip one bit
  }
  json2.ciphertext = toBase64(ctBytes);
  let tamperOk = false;
  try {
    // eslint-disable-next-line no-unused-vars
    const ignored = await decryptBytesXChaCha(json2, testPassword);
    tamperOk = false;
  } catch (e) {
    tamperOk = true;
  }
  if (!tamperOk) {
    logTest("❌ Tampering NOT detected.");
    zeroBytes(testPlaintext);
    return;
  }
  logTest("✅ Tampering properly detected (decryption failed).");

  // 3. Wrong password handling
  logTest("[3] Testing wrong password decryption behavior…");
  const json3 = await encryptBytesXChaCha(testPlaintext, testPassword);
  let wrongPasswordOk = false;
  try {
    // eslint-disable-next-line no-unused-vars
    const ignored = await decryptBytesXChaCha(json3, "WrongPassword!@#");
    wrongPasswordOk = false;
  } catch (e) {
    wrongPasswordOk = true;
  }
  if (!wrongPasswordOk) {
    logTest("❌ Wrong password was accepted unexpectedly.");
    zeroBytes(testPlaintext);
    return;
  }
  logTest("✅ Wrong password correctly rejected.");

  // 4. Randomness quality (basic sanity check)
  logTest("[4] Testing RNG sanity (distribution check)…");
  const sample = randomBytes(2048);
  const seen = new Set();
  for (let i = 0; i < sample.length; i += 1) {
    seen.add(sample[i]);
  }
  logTest(
    "Distinct byte values observed in 2048-byte sample: " + seen.size
  );
  if (seen.size < 128) {
    logTest("❌ RNG distribution looks suspiciously low-entropy.");
    zeroBytes(testPlaintext);
    return;
  }
  logTest("✅ RNG appears reasonably well-distributed (sanity check only).");

  zeroBytes(testPlaintext);
  logTest("All self-tests passed.");
}

/************************************************************
 * UI wiring
 ************************************************************/

function setupUI() {
  const passwordInput = document.getElementById("password");
  const plaintextTextArea = document.getElementById("plaintext");
  const ciphertextTextArea = document.getElementById("ciphertext-json");
  const textStatus = document.getElementById("text-status");
  const fileStatus = document.getElementById("file-status");
  const fileInput = document.getElementById("file-input");
  const fileDecryptInput = document.getElementById("file-decrypt-input");

  // Password strength
  passwordInput.addEventListener("input", updatePasswordStrengthUI);
  updatePasswordStrengthUI();

  // Encrypt text
  document
    .getElementById("encrypt-text-btn")
    .addEventListener("click", async () => {
      const password = passwordInput.value;
      const plaintext = plaintextTextArea.value;

      textStatus.textContent = "";
      textStatus.className = "status";

      if (!password) {
        textStatus.textContent = "Please enter a password.";
        textStatus.className = "status error";
        return;
      }
      if (!plaintext) {
        textStatus.textContent = "Please enter some plaintext to encrypt.";
        textStatus.className = "status error";
        return;
      }

      try {
        const plaintextBytes = utf8ToBytes(plaintext);
        const json = await encryptBytesXChaCha(plaintextBytes, password);
        ciphertextTextArea.value = JSON.stringify(json, null, 2);
        zeroBytes(plaintextBytes);

        textStatus.textContent = "Text encrypted successfully.";
        textStatus.className = "status ok";
      } catch (e) {
        textStatus.textContent = "Encryption error: " + e.message;
        textStatus.className = "status error";
      }
    });

  // Decrypt text
  document
    .getElementById("decrypt-text-btn")
    .addEventListener("click", async () => {
      const password = passwordInput.value;
      const jsonText = ciphertextTextArea.value.trim();

      textStatus.textContent = "";
      textStatus.className = "status";

      if (!password) {
        textStatus.textContent = "Please enter a password.";
        textStatus.className = "status error";
        return;
      }
      if (!jsonText) {
        textStatus.textContent = "Please paste encrypted JSON to decrypt.";
        textStatus.className = "status error";
        return;
      }

      let json;
      try {
        json = JSON.parse(jsonText);
      } catch (e) {
        textStatus.textContent = "Invalid JSON: " + e.message;
        textStatus.className = "status error";
        return;
      }

      try {
        const plaintextBytes = await decryptBytesXChaCha(json, password);
        const plaintext = bytesToUtf8(plaintextBytes);
        plaintextTextArea.value = plaintext;
        zeroBytes(plaintextBytes);

        textStatus.textContent = "Text decrypted successfully.";
        textStatus.className = "status ok";
      } catch (e) {
        textStatus.textContent = e.message;
        textStatus.className = "status error";
      }
    });

  // Clear text
  document.getElementById("clear-text-btn").addEventListener("click", () => {
    plaintextTextArea.value = "";
    ciphertextTextArea.value = "";
    textStatus.textContent = "";
    textStatus.className = "status";
  });

  // Copy encrypted JSON
  document
    .getElementById("copy-json-btn")
    .addEventListener("click", async () => {
      const jsonText = ciphertextTextArea.value.trim();
      if (!jsonText) {
        textStatus.textContent = "No encrypted JSON to copy.";
        textStatus.className = "status error";
        return;
      }
      await secureCopyToClipboard(jsonText, textStatus);
    });

  // Encrypt file
  document
    .getElementById("encrypt-file-btn")
    .addEventListener("click", async () => {
      const password = passwordInput.value;
      const file = fileInput.files && fileInput.files[0];

      fileStatus.textContent = "";
      fileStatus.className = "status";

      if (!password) {
        fileStatus.textContent = "Please enter a password.";
        fileStatus.className = "status error";
        return;
      }
      if (!file) {
        fileStatus.textContent = "Please choose a file to encrypt.";
        fileStatus.className = "status error";
        return;
      }

      try {
        const arrayBuffer = await file.arrayBuffer();
        const plaintextBytes = new Uint8Array(arrayBuffer);
        const json = await encryptBytesXChaCha(plaintextBytes, password);

        json.originalFilename = file.name;
        json.originalMimeType = file.type || "application/octet-stream";

        const blob = new Blob([JSON.stringify(json, null, 2)], {
          type: "application/json"
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = file.name + ".enc.json";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        zeroBytes(plaintextBytes);

        fileStatus.textContent = "File encrypted and downloaded as JSON.";
        fileStatus.className = "status ok";
      } catch (e) {
        fileStatus.textContent = "File encryption error: " + e.message;
        fileStatus.className = "status error";
      }
    });

  // Decrypt file
  document
    .getElementById("decrypt-file-btn")
    .addEventListener("click", async () => {
      const password = passwordInput.value;
      const file = fileDecryptInput.files && fileDecryptInput.files[0];

      fileStatus.textContent = "";
      fileStatus.className = "status";

      if (!password) {
        fileStatus.textContent = "Please enter a password.";
        fileStatus.className = "status error";
        return;
      }
      if (!file) {
        fileStatus.textContent =
          "Please choose an encrypted JSON file to decrypt.";
        fileStatus.className = "status error";
        return;
      }

      try {
        const text = await file.text();
        const json = JSON.parse(text);

        const plaintextBytes = await decryptBytesXChaCha(json, password);
        const blob = new Blob([plaintextBytes], {
          type: json.originalMimeType || "application/octet-stream"
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = json.originalFilename || "decrypted.bin";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        zeroBytes(plaintextBytes);

        fileStatus.textContent = "File decrypted and downloaded.";
        fileStatus.className = "status ok";
      } catch (e) {
        fileStatus.textContent = "File decryption error: " + e.message;
        fileStatus.className = "status error";
      }
    });

  // Self tests
  document
    .getElementById("run-tests-btn")
    .addEventListener("click", runSelfTests);
}

// Wait for DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", setupUI);
} else {
  setupUI();
}
