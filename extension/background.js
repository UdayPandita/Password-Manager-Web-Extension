// LPH Password Manager - Background Service Worker
// Local-only authentication with master password encryption

// Session state
let session = {
  key: null,
  salt: null,
  vaultKey: null,
  unlocked: false,
  user: null,
};

// Storage keys
const STORAGE_KEYS = {
  SALT: 'pm_salt',
  VERIFIER: 'pm_verifier',
  DATA: 'pm_data',
  LOCAL_USER: 'pm_local_user',
  ENCRYPTED_VAULT_KEY: 'pm_encrypted_vault_key',
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

// Encrypt/Decrypt raw bytes (Uint8Array) with AES-GCM
async function encryptBytes(bytes, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  const out = new Uint8Array(iv.byteLength + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.byteLength);
  return bytesToBase64(out);
}

async function decryptBytes(b64, key) {
  const all = base64ToBytes(b64);
  const iv = all.slice(0, 12);
  const ct = all.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(pt);
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

// Derive a vault key (AES-GCM 256) from a mnemonic phrase using PBKDF2 (BIP-39 style)
async function deriveVaultKeyFromMnemonic(mnemonic, passphrase = '') {
  const enc = new TextEncoder();
  const password = enc.encode(mnemonic.normalize('NFKD'));
  const saltStr = 'mnemonic' + (passphrase || '');
  const salt = enc.encode(saltStr.normalize('NFKD'));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 2048, hash: 'SHA-512' },
    keyMaterial,
    512
  );

  const bytes = new Uint8Array(bits);
  // Use first 32 bytes (256 bits) as AES key
  const keyBytes = bytes.slice(0, 32);
  return await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// Return raw key bytes (32 bytes) derived from mnemonic (useful for storing encrypted key)
async function deriveVaultKeyRaw(mnemonic, passphrase = '') {
  const enc = new TextEncoder();
  const password = enc.encode(mnemonic.normalize('NFKD'));
  const saltStr = 'mnemonic' + (passphrase || '');
  const salt = enc.encode(saltStr.normalize('NFKD'));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    password,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 2048, hash: 'SHA-512' },
    keyMaterial,
    512
  );

  const bytes = new Uint8Array(bits);
  return bytes.slice(0, 32);
}

// A small 256-word list used for generating a human-friendly mnemonic.
// Note: This is a compact list (256 words). For production/BIP-39 compatibility
// consider replacing with a full BIP-39 wordlist or library.
const WORDLIST = [
  'apple','arm','able','angle','ant','arch','army','aunt','away','baby','back','bake','ball','band','bank','bar',
  'base','bath','beach','bear','beat','bed','bee','bell','belt','bench','bend','best','bird','birth','bit','bite',
  'black','blade','blame','blend','bless','blind','block','blood','blow','blue','board','boat','body','bolt','bone','book',
  'boom','boot','border','bottle','box','boy','brain','branch','brave','bread','break','brick','bridge','bright','bring','broad',
  'broom','brown','brush','bubble','bucket','build','bulb','bulk','bull','burn','burst','bus','bush','busy','butter','button',
  'cable','cage','cake','call','calm','camera','camp','canal','candle','candy','canvas','cap','car','card','care','carry',
  'cart','case','cash','cast','catch','cause','cave','ceiling','cell','cent','chain','chair','chalk','chance','change','chart',
  'check','cheese','chef','chest','chicken','child','chip','choice','choose','chore','circle','city','claim','class','clean','clear',
  'climb','clock','close','cloth','cloud','club','coach','coal','coast','coat','code','coffee','coil','coin','cold','collect',
  'color','combine','come','comfort','comic','command','common','company','compare','compass','complete','computer','concert','condition','connect','consider',
  'contact','contain','content','contest','context','control','cook','cool','copy','corner','correct','cost','cotton','couch','could','count',
  'country','course','court','cover','cow','crack','craft','crane','crash','crawl','create','credit','crew','cricket','crime','crisp',
  'cross','crowd','crown','cruise','crush','cry','culture','cup','curious','current','curve','custom','cute','cycle','daily','damage',
  'dance','danger','dark','data','date','daughter','dawn','day','deal','debate','decide','decline','deer','define','degree','delay',
  'deliver','demand','deny','depend','depth','describe','desert','design','desk','detail','detect','develop','device','devote','dialog','diamond',
  'diary','dictate','die','diet','difference','different','difficult','dig','digital','dinner','direct','dirt','dirty','discuss','disease','dish',
  'disk','display','distance','divide','doctor','document','dog','doll','domain','door','double','doubt','down','draft','dragon','drama',
  'draw','dream','dress','drift','drink','drive','drop','drug','drum','dry','duck','dumb','dust','duty','dynamic','eagle',
  'ear','early','earn','earth','ease','east','easy','echo','edge','edit','educate','effect','effort','egg','eight','either',
  'elbow','elder','electric','elegant','element','elephant','elevator','elite','else','empty','enable','end','enemy','energy','engine','enjoy',
  'enough','enter','entry','envelope','equal','equipment','error','escape','especially','estate','estimate','even','evening','event','ever','every',
  'exact','exam','example','excite','exit','expand','expect','expense','experience','expert','explain','express','extend','extra','eye','face'
];

// Generate a 12-word mnemonic from the WORDLIST
function generateMnemonic() {
  const indices = new Uint8Array(12);
  crypto.getRandomValues(indices);
  const words = [];
  for (let i = 0; i < 12; i++) {
    // Map byte (0-255) to wordlist index
    words.push(WORDLIST[indices[i] % WORDLIST.length]);
  }
  return words.join(' ');
}

// Temporary session storage for signup flow
// session.tempSignup = { email, password }
// session.mnemonic = '...'

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
  
  // Create a random vault key (K_vault) and store it encrypted by the master key
  try {
    const vaultRaw = crypto.getRandomValues(new Uint8Array(32));
    const encVault = await encryptBytes(vaultRaw, session.key);
    await chrome.storage.local.set({ [STORAGE_KEYS.ENCRYPTED_VAULT_KEY]: encVault });
    session.vaultKey = await crypto.subtle.importKey('raw', vaultRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  } catch (e) {
    console.warn('Failed to create vault key during signup', e);
    session.vaultKey = null;
  }

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
  
  // If there is no encrypted vault key yet (first time), create one and store it encrypted by master key
  const encStored = await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTED_VAULT_KEY);
  if (!encStored[STORAGE_KEYS.ENCRYPTED_VAULT_KEY]) {
    try {
      const vaultRaw = crypto.getRandomValues(new Uint8Array(32));
      const encVault = await encryptBytes(vaultRaw, session.key);
      await chrome.storage.local.set({ [STORAGE_KEYS.ENCRYPTED_VAULT_KEY]: encVault });
      session.vaultKey = await crypto.subtle.importKey('raw', vaultRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    } catch (e) {
      console.warn('Failed to create vault key in setMasterPassword', e);
      session.vaultKey = null;
    }
  } else {
    // Try to decrypt existing vault key into session
    try {
      const vaultBytes = await decryptBytes(encStored[STORAGE_KEYS.ENCRYPTED_VAULT_KEY], session.key);
      session.vaultKey = await crypto.subtle.importKey('raw', vaultBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    } catch (e) {
      session.vaultKey = null;
    }
  }

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

      // Attempt to load encrypted vault key (K_vault) and decrypt it with master key
      const encStored = await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTED_VAULT_KEY);
      const encVault = encStored[STORAGE_KEYS.ENCRYPTED_VAULT_KEY];
      if (encVault) {
        try {
          const vaultBytes = await decryptBytes(encVault, session.key);
          // Import as AES-GCM key
          session.vaultKey = await crypto.subtle.importKey('raw', vaultBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
        } catch (e) {
          // Couldn't decrypt vault key - leave vaultKey null and fallback to session.key later
          console.warn('Failed to decrypt vault key:', e);
          session.vaultKey = null;
        }
      } else {
        session.vaultKey = null;
      }

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
    // Use vaultKey (derived from mnemonic) if available, otherwise fall back to master key
    const keyToUse = session.vaultKey || session.key;
    return await decryptJson(blob, keyToUse);
  } catch (e) {
    console.error('Decrypt failed', e);
    throw new Error('Decrypt failed');
  }
}

async function saveAllData(obj) {
  if (!session.unlocked || !session.key) throw new Error('Locked');
  // Use vaultKey (derived from mnemonic) if available, otherwise fall back to master key
  const keyToUse = session.vaultKey || session.key;
  const blob = await encryptJson(obj, keyToUse);
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
        case 'PM_GENERATE_MNEMONIC': {
          // Begin a signup flow that requires mnemonic confirmation.
          const { email, password } = msg;
          // Temporarily store signup data in session until verification
          session.tempSignup = { email, password };
          const mnemonic = generateMnemonic();
          session.mnemonic = mnemonic;
          sendResponse({ ok: true, mnemonic });
          break;
        }
        case 'PM_GET_MNEMONIC': {
          sendResponse({ ok: true, mnemonic: session.mnemonic || null });
          break;
        }
        case 'PM_VERIFY_MNEMONIC': {
          const { mnemonic } = msg;
          if (!session.tempSignup || !session.mnemonic) {
            sendResponse({ ok: false, error: 'No signup in progress' });
            break;
          }
          if ((mnemonic || '').trim() !== session.mnemonic) {
            sendResponse({ ok: false, error: 'Mnemonic does not match' });
            break;
          }

          // Complete account creation using stored tempSignup
          const { email, password } = session.tempSignup;

          // Create salt and master key
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const saltB64 = bytesToBase64(salt);
          await chrome.storage.local.set({ [STORAGE_KEYS.SALT]: saltB64 });
          session.salt = salt;
          session.key = await deriveKeyFromPassword(password, salt);

          // Create verifier and store
          const verifierBlob = await encryptJson({ v: 'ok' }, session.key);
          await chrome.storage.local.set({ [STORAGE_KEYS.VERIFIER]: verifierBlob });

          // Derive vault key raw bytes and encrypt them with master key for storage
          const vaultRaw = await deriveVaultKeyRaw(session.mnemonic);
          const encVault = await encryptBytes(vaultRaw, session.key);
          await chrome.storage.local.set({ [STORAGE_KEYS.ENCRYPTED_VAULT_KEY]: encVault });

          // Import vaultKey into session
          session.vaultKey = await crypto.subtle.importKey('raw', vaultRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

          // Store user record
          const userObj = { email, salt: saltB64 };
          await chrome.storage.local.set({ [STORAGE_KEYS.LOCAL_USER]: userObj });

          // Mark session as signed in/unlocked and clear temp
          session.user = { email };
          session.unlocked = true;
          delete session.tempSignup;
          delete session.mnemonic;

          sendResponse({ ok: true, user: session.user });
          break;
        }
        case 'PM_RECOVER_ACCOUNT': {
          // Recover account given mnemonic and new master password
          const { mnemonic, newPassword } = msg;
          if (!mnemonic || !newPassword) {
            sendResponse({ ok: false, error: 'Missing fields' });
            break;
          }

          // Derive vault raw key from mnemonic
          const vaultRaw = await deriveVaultKeyRaw(mnemonic);

          // Use existing salt if available, otherwise create
          let saltObj = await chrome.storage.local.get(STORAGE_KEYS.SALT);
          let saltB64 = saltObj[STORAGE_KEYS.SALT];
          let salt;
          if (!saltB64) {
            salt = crypto.getRandomValues(new Uint8Array(16));
            saltB64 = bytesToBase64(salt);
            await chrome.storage.local.set({ [STORAGE_KEYS.SALT]: saltB64 });
          } else {
            salt = base64ToBytes(saltB64);
          }

          // Derive new master key from newPassword
          const newMasterKey = await deriveKeyFromPassword(newPassword, salt);

          // Store new verifier
          const verifierBlob = await encryptJson({ v: 'ok' }, newMasterKey);
          await chrome.storage.local.set({ [STORAGE_KEYS.VERIFIER]: verifierBlob });

          // Encrypt vault raw with new master key and store
          const encVault = await encryptBytes(vaultRaw, newMasterKey);
          await chrome.storage.local.set({ [STORAGE_KEYS.ENCRYPTED_VAULT_KEY]: encVault });

          // Keep session cleared - user must sign in with new password
          session.user = null;
          session.key = null;
          session.vaultKey = null;
          session.unlocked = false;

          sendResponse({ ok: true });
          break;
        }
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