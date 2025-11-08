// LPH Password Manager - Background Service Worker
// Local-only authentication with master password encryption

// Session state
let session = {
  key: null,
  salt: null,
  unlocked: false,
  user: null,
};

// Storage keys
const STORAGE_KEYS = {
  SALT: 'pm_salt',
  VERIFIER: 'pm_verifier',
  DATA: 'pm_data',
  LOCAL_USER: 'pm_local_user',
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
  return await crypto.subtle.deriveKey(
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

// ----- Authentication (local only) -----
// Use PBKDF2 for password hashing with per-user salt
async function derivePbkdf2(password, saltBytes, iterations = 200000, lengthBytes = 32) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    lengthBytes * 8
  );

  return new Uint8Array(bits);
}

async function signUp(email, password) {
  // Check if user already exists
  const existing = await chrome.storage.local.get(STORAGE_KEYS.LOCAL_USER);
  if (existing && existing[STORAGE_KEYS.LOCAL_USER]) {
    return { ok: false, error: 'User already exists' };
  }

  // Create a single salt for both authentication and vault encryption
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = bytesToBase64(salt);
  
  // Store salt for both purposes
  await chrome.storage.local.set({ [STORAGE_KEYS.SALT]: saltB64 });
  
  // Create encryption key (CryptoKey for AES-GCM)
  session.salt = salt;
  session.key = await deriveKeyFromPassword(password, salt);
  
  // Create verifier for unlock validation
  const verifierBlob = await encryptJson({ v: 'ok' }, session.key);
  await chrome.storage.local.set({ [STORAGE_KEYS.VERIFIER]: verifierBlob });
  
  // Store user account (email only, password verified via verifier)
  const userObj = { email, salt: saltB64 };
  await chrome.storage.local.set({ [STORAGE_KEYS.LOCAL_USER]: userObj });
  
  // Set user in session
  session.user = { email };
  session.unlocked = true;
  
  return { ok: true, user: session.user };
}

async function signIn(email, password) {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.LOCAL_USER);
  const obj = stored[STORAGE_KEYS.LOCAL_USER];
  
  if (!obj) {
    return { ok: false, error: 'No account found' };
  }
  
  if (obj.email !== email) {
    return { ok: false, error: 'Invalid email or password' };
  }
  
  // Set user in session first
  session.user = { email };
  
  // Try to unlock vault with password
  const unlockResult = await unlock(password);
  if (!unlockResult.ok) {
    session.user = null; // Clear user if unlock fails
    return { ok: false, error: 'Invalid email or password' };
  }
  
  return { ok: true, user: session.user };
}

async function signOut() {
  // Clear session but keep user account data so they can sign in again
  session.user = null;
  session.key = null;
  session.unlocked = false;
  return { ok: true };
}

// ----- Master password management -----
async function setMasterPassword(password) {
  session.salt = await getSalt();
  session.key = await deriveKeyFromPassword(password, session.salt);
  
  const verifierBlob = await encryptJson({ v: 'ok' }, session.key);
  await chrome.storage.local.set({ [STORAGE_KEYS.VERIFIER]: verifierBlob });
  
  session.unlocked = true;
  
  return { ok: true };
}

async function unlock(password) {
  const salt = await getSalt();
  const stored = await chrome.storage.local.get(STORAGE_KEYS.VERIFIER);
  const verifier = stored[STORAGE_KEYS.VERIFIER];
  
  const key = await deriveKeyFromPassword(password, salt);
  
  if (!verifier) {
    session.key = key;
    session.salt = salt;
    session.unlocked = true;
    return { ok: true, firstTime: true };
  }
  
  try {
    const check = await decryptJson(verifier, key);
    if (check && check.v === 'ok') {
      session.key = key;
      session.salt = salt;
      session.unlocked = true;
      return { ok: true };
    }
  } catch (e) {
    // Wrong password
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

// ----- Icon loading -----
async function setActionIconIfAvailable() {
  try {
    const url = chrome.runtime.getURL('icons/logo.png');
    const res = await fetch(url);
    if (!res.ok) return;
    const blob = await res.blob();
    const bmp = await createImageBitmap(blob);
    const sizes = [16, 32, 48, 128];
    const imageData = {};
    for (const s of sizes) {
      imageData[s] = imageToImageData(bmp, s, s);
    }
    await chrome.action.setIcon({ imageData });
  } catch (e) {
    // No logo yet
  }
}

function imageToImageData(img, w, h) {
  const canvas = new OffscreenCanvas(w, h);
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  const ratio = Math.max(w / img.width, h / img.height);
  const nw = Math.round(img.width * ratio);
  const nh = Math.round(img.height * ratio);
  const dx = Math.round((w - nw) / 2);
  const dy = Math.round((h - nh) / 2);
  ctx.drawImage(img, dx, dy, nw, nh);
  return ctx.getImageData(0, 0, w, h);
}

setActionIconIfAvailable();

// ----- Message handling -----
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'PM_SIGNUP':
          sendResponse(await signUp(msg.email, msg.password));
          break;
        case 'PM_SIGNIN':
          sendResponse(await signIn(msg.email, msg.password));
          break;
        case 'PM_SIGNOUT':
          sendResponse(await signOut());
          break;
        case 'PM_GET_USER':
          sendResponse({ ok: true, user: session.user });
          break;
        case 'PM_SET_MASTER':
          sendResponse(await setMasterPassword(msg.password));
          break;
        case 'PM_UNLOCK':
          sendResponse(await unlock(msg.password));
          break;
        case 'PM_LOCK':
          sendResponse(lock());
          break;
        case 'PM_STATUS': {
          const stored = await chrome.storage.local.get(STORAGE_KEYS.LOCAL_USER);
          const localUserExists = !!(stored && stored[STORAGE_KEYS.LOCAL_USER]);
          sendResponse({ 
            unlocked: session.unlocked,
            user: session.user ? { email: session.user.email } : null,
            localUserExists,
          });
          break;
        }
        case 'PM_SAVE_CREDENTIALS': {
          if (!session.unlocked) throw new Error('Locked');
          const { url, username, password } = msg;
          const domain = domainFromUrl(url);
          if (!domain) throw new Error('Bad URL');
          const all = await loadAllData();
          if (!all[domain]) all[domain] = [];
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
          const credentials = all[domain] || [];
          sendResponse({ ok: true, credentials });
          break;
        }
        case 'PM_GET_ALL': {
          if (!session.unlocked) throw new Error('Locked');
          const all = await loadAllData();
          sendResponse({ ok: true, data: all });
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
        case 'PM_WIPE_ALL':
          await chrome.storage.local.clear();
          lock();
          sendResponse({ ok: true });
          break;
        default:
          sendResponse({ ok: false, error: 'Unknown message' });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e.message || String(e) });
    }
  })();
  return true;
});