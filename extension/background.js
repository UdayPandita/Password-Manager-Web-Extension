// LPH Password Manager - Background Service Worker (MV3)
// Handles encryption, storage, messaging, and (optionally) setting the action icon if an image is provided.

// In-memory session state (cleared when service worker is suspended)
let session = {
  key: null, // CryptoKey derived from master password
  salt: null, // Uint8Array
  unlocked: false,
};

const STORAGE_KEYS = {
  SALT: 'pm_salt',
  VERIFIER: 'pm_verifier',
  DATA: 'pm_data', // object domain -> encrypted blob (base64)
};

// ----- Crypto helpers -----
async function getSalt() {
  const { [STORAGE_KEYS.SALT]: b64 } = await chrome.storage.local.get(STORAGE_KEYS.SALT);
  if (b64) return base64ToBytes(b64);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  await chrome.storage.local.set({ [STORAGE_KEYS.SALT]: bytesToBase64(salt) });
  return salt;
}

async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 200000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  return key;
}

async function encryptJson(obj, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const out = new Uint8Array(iv.byteLength + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.byteLength);
  return bytesToBase64(out);
}

async function decryptJson(b64, key) {
  const all = base64ToBytes(b64);
  const iv = all.slice(0, 12);
  const ct = all.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ----- Master password management -----
async function setMasterPassword(password) {
  session.salt = await getSalt();
  session.key = await deriveKeyFromPassword(password, session.salt);
  // store verifier: encrypt a known constant
  const verifierBlob = await encryptJson({ v: 'ok' }, session.key);
  await chrome.storage.local.set({ [STORAGE_KEYS.VERIFIER]: verifierBlob });
  session.unlocked = true;
  return { ok: true };
}

async function unlock(password) {
  const salt = await getSalt();
  const key = await deriveKeyFromPassword(password, salt);
  const { [STORAGE_KEYS.VERIFIER]: blob } = await chrome.storage.local.get(STORAGE_KEYS.VERIFIER);
  if (!blob) {
    // No verifier set yet => treat as first-time set
    session.key = key;
    session.salt = salt;
    session.unlocked = true;
    return { ok: true, firstTime: true };
  }
  try {
    const check = await decryptJson(blob, key);
    if (check && check.v === 'ok') {
      session.key = key;
      session.salt = salt;
      session.unlocked = true;
      return { ok: true };
    }
  } catch (e) {
    // ignore
  }
  return { ok: false, error: 'Invalid master password' };
}

function lock() {
  session.key = null;
  session.unlocked = false;
  return { ok: true };
}

// ----- Data access -----
async function loadAllData() {
  const { [STORAGE_KEYS.DATA]: blob } = await chrome.storage.local.get(STORAGE_KEYS.DATA);
  if (!blob) return {};
  if (!session.unlocked || !session.key) throw new Error('Locked');
  try {
    return await decryptJson(blob, session.key);
  } catch (e) {
    console.error('Decrypt failed', e);
    throw new Error('Decrypt failed');
  }
}

async function saveAllData(obj) {
  if (!session.unlocked || !session.key) throw new Error('Locked');
  const blob = await encryptJson(obj, session.key);
  await chrome.storage.local.set({ [STORAGE_KEYS.DATA]: blob });
}

function domainFromUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    return null;
  }
}

// ----- Optional: Set action icon from provided image if present -----
async function setActionIconIfAvailable() {
  try {
    const url = chrome.runtime.getURL('icons/logo.png');
    const res = await fetch(url);
    if (!res.ok) return; // likely not provided yet
    const blob = await res.blob();
    const bmp = await createImageBitmap(blob);
    const sizes = [16, 32, 48, 128];
    const imageData = {};
    for (const s of sizes) {
      imageData[s] = imageToImageData(bmp, s, s);
    }
    await chrome.action.setIcon({ imageData });
  } catch (e) {
    // No logo provided yet or unsupported in this context; ignore
  }
}

function imageToImageData(img, w, h) {
  const canvas = new OffscreenCanvas(w, h);
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  // cover fit
  const ratio = Math.max(w / img.width, h / img.height);
  const nw = Math.round(img.width * ratio);
  const nh = Math.round(img.height * ratio);
  const dx = Math.round((w - nw) / 2);
  const dy = Math.round((h - nh) / 2);
  ctx.drawImage(img, dx, dy, nw, nh);
  return ctx.getImageData(0, 0, w, h);
}

setActionIconIfAvailable();

// ----- Messaging -----
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'PM_SET_MASTER': {
          const res = await setMasterPassword(msg.password);
          sendResponse(res);
          break;
        }
        case 'PM_UNLOCK': {
          const res = await unlock(msg.password);
          sendResponse(res);
          break;
        }
        case 'PM_LOCK': {
          sendResponse(lock());
          break;
        }
        case 'PM_STATUS': {
          sendResponse({ unlocked: session.unlocked });
          break;
        }
        case 'PM_SAVE_CREDENTIALS': {
          if (!session.unlocked) throw new Error('Locked');
          const { url, username, password } = msg;
          const domain = domainFromUrl(url);
          if (!domain) throw new Error('Bad URL');
          const all = await loadAllData();
          if (!all[domain]) all[domain] = [];
          // Avoid duplicates
          if (!all[domain].some(c => c.username === username)) {
            all[domain].push({ username, password });
          }
          await saveAllData(all);
          sendResponse({ ok: true });
          break;
        }
        case 'PM_GET_CREDENTIALS': {
          if (!session.unlocked) throw new Error('Locked');
          const { url } = msg;
          const domain = domainFromUrl(url);
          const all = await loadAllData();
          sendResponse({ ok: true, credentials: all[domain] || [] });
          break;
        }
        case 'PM_DELETE_CREDENTIAL': {
          if (!session.unlocked) throw new Error('Locked');
          const { url, username } = msg;
          const domain = domainFromUrl(url);
          const all = await loadAllData();
          if (all[domain]) {
            all[domain] = all[domain].filter(c => c.username !== username);
            if (all[domain].length === 0) delete all[domain];
            await saveAllData(all);
          }
          sendResponse({ ok: true });
          break;
        }
        case 'PM_WIPE_ALL': {
          await chrome.storage.local.clear();
          lock();
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: 'Unknown message' });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e.message || String(e) });
    }
  })();
  // Return true to indicate async response
  return true;
});
