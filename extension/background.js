// LPH Password Manager - Background Service Worker with Supabase Sync
// CSP-compliant version - no eval()

// Import config directly (works because it's a module)
import { SUPABASE_CONFIG } from './config.js';

// Supabase client will be loaded dynamically
let supabaseClient = null;

// Session state
let session = {
  key: null,
  salt: null,
  unlocked: false,
  user: null,
  syncEnabled: false,
};

const STORAGE_KEYS = {
  SALT: 'pm_salt',
  VERIFIER: 'pm_verifier',
  DATA: 'pm_data',
  SUPABASE_SESSION: 'pm_supabase_session',
  SYNC_ENABLED: 'pm_sync_enabled',
  LAST_SYNC: 'pm_last_sync',
};

// ----- Supabase initialization -----
async function initSupabase() {
  if (supabaseClient) return supabaseClient;
  
  try {
    // Import Supabase from CDN
    const { createClient } = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm');
    
    supabaseClient = createClient(SUPABASE_CONFIG.url, SUPABASE_CONFIG.anonKey);
    
    // Restore session if exists
    const stored = await chrome.storage.local.get(STORAGE_KEYS.SUPABASE_SESSION);
    if (stored[STORAGE_KEYS.SUPABASE_SESSION]) {
      const { data } = await supabaseClient.auth.setSession(stored[STORAGE_KEYS.SUPABASE_SESSION]);
      if (data.session) {
        session.user = data.session.user;
        session.syncEnabled = true;
      }
    }
    
    return supabaseClient;
  } catch (error) {
    console.error('Failed to initialize Supabase:', error);
    throw error;
  }
}

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

// ----- Supabase Auth -----
async function signUp(email, password) {
  const sb = await initSupabase();
  const { data, error } = await sb.auth.signUp({ email, password });
  if (error) throw new Error(error.message);
  
  if (data.session) {
    await chrome.storage.local.set({
      [STORAGE_KEYS.SUPABASE_SESSION]: data.session,
    });
    session.user = data.user;
    session.syncEnabled = true;
  }
  
  return { ok: true, user: data.user };
}

async function signIn(email, password) {
  const sb = await initSupabase();
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error) throw new Error(error.message);
  
  await chrome.storage.local.set({
    [STORAGE_KEYS.SUPABASE_SESSION]: data.session,
  });
  session.user = data.user;
  session.syncEnabled = true;
  
  return { ok: true, user: data.user };
}

async function signOut() {
  const sb = await initSupabase();
  await sb.auth.signOut();
  await chrome.storage.local.remove(STORAGE_KEYS.SUPABASE_SESSION);
  session.user = null;
  session.syncEnabled = false;
  return { ok: true };
}

// ----- Sync with Supabase -----
async function pushVaultToCloud() {
  if (!session.syncEnabled || !session.user) return;
  
  const sb = await initSupabase();
  const saltB64 = bytesToBase64(session.salt);
  const { [STORAGE_KEYS.VERIFIER]: verifier, [STORAGE_KEYS.DATA]: encryptedData } = 
    await chrome.storage.local.get([STORAGE_KEYS.VERIFIER, STORAGE_KEYS.DATA]);
  
  const { error } = await sb
    .from('vaults')
    .upsert({
      user_id: session.user.id,
      salt: saltB64,
      verifier: verifier || '',
      encrypted_data: encryptedData || '',
      updated_at: new Date().toISOString(),
    });
  
  if (error) throw new Error(`Sync failed: ${error.message}`);
  
  await chrome.storage.local.set({
    [STORAGE_KEYS.LAST_SYNC]: new Date().toISOString(),
  });
}

async function pullVaultFromCloud() {
  if (!session.syncEnabled || !session.user) return null;
  
  const sb = await initSupabase();
  const { data, error } = await sb
    .from('vaults')
    .select('*')
    .eq('user_id', session.user.id)
    .single();
  
  if (error && error.code !== 'PGRST116') {
    throw new Error(`Pull failed: ${error.message}`);
  }
  
  if (!data) return null;
  
  return {
    salt: data.salt,
    verifier: data.verifier,
    encryptedData: data.encrypted_data,
    updatedAt: data.updated_at,
  };
}

// ----- Master password management -----
async function setMasterPassword(password) {
  session.salt = await getSalt();
  session.key = await deriveKeyFromPassword(password, session.salt);
  
  const verifierBlob = await encryptJson({ v: 'ok' }, session.key);
  await chrome.storage.local.set({ [STORAGE_KEYS.VERIFIER]: verifierBlob });
  
  session.unlocked = true;
  
  if (session.syncEnabled) {
    try {
      await pushVaultToCloud();
    } catch (e) {
      console.error('Push failed:', e);
    }
  }
  
  return { ok: true };
}

async function unlock(password) {
  let cloudVault = null;
  if (session.syncEnabled) {
    try {
      cloudVault = await pullVaultFromCloud();
    } catch (e) {
      console.error('Pull failed:', e);
    }
  }
  
  let salt, verifier;
  if (cloudVault) {
    salt = base64ToBytes(cloudVault.salt);
    verifier = cloudVault.verifier;
    await chrome.storage.local.set({
      [STORAGE_KEYS.SALT]: cloudVault.salt,
      [STORAGE_KEYS.VERIFIER]: cloudVault.verifier,
      [STORAGE_KEYS.DATA]: cloudVault.encryptedData,
    });
  } else {
    salt = await getSalt();
    const stored = await chrome.storage.local.get(STORAGE_KEYS.VERIFIER);
    verifier = stored[STORAGE_KEYS.VERIFIER];
  }
  
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
  
  if (session.syncEnabled) {
    try {
      await pushVaultToCloud();
    } catch (e) {
      console.error('Auto-sync failed:', e);
    }
  }
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
        case 'PM_STATUS':
          sendResponse({ 
            unlocked: session.unlocked,
            syncEnabled: session.syncEnabled,
            user: session.user ? { email: session.user.email } : null,
          });
          break;
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
        case 'PM_SYNC_NOW':
          if (session.syncEnabled) {
            await pushVaultToCloud();
            sendResponse({ ok: true, synced: new Date().toISOString() });
          } else {
            sendResponse({ ok: false, error: 'Sync not enabled' });
          }
          break;
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