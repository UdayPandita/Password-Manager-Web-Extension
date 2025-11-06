// LPH Password Manager - Enhanced Popup with Sync

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || '';
}

async function getStatus() {
  return chrome.runtime.sendMessage({ type: 'PM_STATUS' });
}

async function unlock(password) {
  return chrome.runtime.sendMessage({ type: 'PM_UNLOCK', password });
}

async function lock() {
  return chrome.runtime.sendMessage({ type: 'PM_LOCK' });
}

async function getCredentials(url) {
  return chrome.runtime.sendMessage({ type: 'PM_GET_CREDENTIALS', url });
}

async function deleteCredential(url, username) {
  return chrome.runtime.sendMessage({ type: 'PM_DELETE_CREDENTIAL', url, username });
}

async function syncNow() {
  return chrome.runtime.sendMessage({ type: 'PM_SYNC_NOW' });
}

async function signOut() {
  return chrome.runtime.sendMessage({ type: 'PM_SIGNOUT' });
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

async function autofillToTab(tabId, username, password) {
  await chrome.tabs.sendMessage(tabId, {
    type: 'PM_AUTOFILL',
    username,
    password,
  });
}

function updateStatus(status) {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  const lockBtn = document.getElementById('lockBtn');
  const syncBtn = document.getElementById('syncBtn');
  const accountLink = document.getElementById('accountLink');
  
  if (status.unlocked) {
    dot.className = 'status-dot unlocked';
    if (status.syncEnabled) {
      dot.classList.add('synced');
      text.textContent = 'Unlocked & Synced';
    } else {
      text.textContent = 'Unlocked (Local)';
    }
    lockBtn.style.display = 'inline-block';
    syncBtn.style.display = status.syncEnabled ? 'inline-block' : 'none';
  } else {
    dot.className = 'status-dot';
    text.textContent = 'Locked';
    lockBtn.style.display = 'none';
    syncBtn.style.display = 'none';
  }
  
  accountLink.style.display = status.syncEnabled ? 'inline-block' : 'none';
}

function renderSyncInfo(status) {
  const syncInfo = document.getElementById('syncInfo');
  
  if (!status.syncEnabled) {
    syncInfo.style.display = 'block';
    syncInfo.className = 'sync-info signed-out';
    syncInfo.innerHTML = `
      <strong>💡 Sync Disabled</strong>
      <div>Sign in to sync passwords across devices.</div>
      <button id="enableSyncBtn" class="btn-primary">Sign In / Sign Up</button>
    `;
    
    document.getElementById('enableSyncBtn').addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('auth.html') });
    });
  } else if (status.user) {
    syncInfo.style.display = 'block';
    syncInfo.className = 'sync-info';
    syncInfo.innerHTML = `
      <strong>☁️ Synced</strong>
      <div style="font-size: 11px;">Signed in as: ${status.user.email}</div>
      <button id="signOutBtn" style="color: #666; font-size: 11px; padding: 3px 8px;">Sign Out</button>
    `;
    
    document.getElementById('signOutBtn').addEventListener('click', async () => {
      if (confirm('Sign out? Your local data will remain, but sync will be disabled.')) {
        await signOut();
        await render();
      }
    });
  } else {
    syncInfo.style.display = 'none';
  }
}

async function render() {
  const status = await getStatus();
  const url = await getActiveTabUrl();
  
  updateStatus(status);
  renderSyncInfo(status);
  
  document.getElementById('site').textContent = hostFromUrl(url) || '(unknown)';
  
  const lockedView = document.getElementById('lockedView');
  const unlockedView = document.getElementById('unlockedView');
  
  if (!status?.unlocked) {
    lockedView.style.display = 'block';
    unlockedView.style.display = 'none';
  } else {
    lockedView.style.display = 'none';
    unlockedView.style.display = 'block';
    
    const res = await getCredentials(url);
    const list = document.getElementById('creds');
    list.innerHTML = '';
    const noCreds = document.getElementById('noCreds');
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (res?.ok && res.credentials?.length) {
      noCreds.style.display = 'none';
      for (const c of res.credentials) {
        const div = document.createElement('div');
        div.className = 'cred';
        div.innerHTML = `
          <strong>${escapeHtml(c.username)}</strong>
          <div class="cred-actions">
            <button class="fill btn-primary">Autofill</button>
            <button class="del btn-danger">Delete</button>
          </div>
        `;
        
        div.querySelector('.fill').addEventListener('click', async () => {
          try {
            await autofillToTab(tab.id, c.username, c.password);
            window.close();
          } catch (e) {
            alert('Failed to autofill. Please refresh the page and try again.');
          }
        });
        
        div.querySelector('.del').addEventListener('click', async () => {
          if (confirm(`Delete credentials for ${c.username}?`)) {
            await deleteCredential(url, c.username);
            await render();
          }
        });
        
        list.appendChild(div);
      }
    } else {
      noCreds.style.display = 'block';
    }
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Wire up events
document.getElementById('unlockBtn').addEventListener('click', async () => {
  const pwd = document.getElementById('unlockPwd').value;
  if (!pwd) return;
  
  const btn = document.getElementById('unlockBtn');
  btn.disabled = true;
  btn.textContent = 'Unlocking...';
  
  try {
    const res = await unlock(pwd);
    if (!res?.ok) {
      alert(res.error || 'Unlock failed');
    } else {
      await render();
    }
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
  }
});

document.getElementById('lockBtn').addEventListener('click', async () => {
  await lock();
  await render();
});

document.getElementById('syncBtn').addEventListener('click', async () => {
  const btn = document.getElementById('syncBtn');
  btn.disabled = true;
  btn.textContent = '⟳';
  
  try {
    const res = await syncNow();
    if (res?.ok) {
      // Show brief success indicator
      btn.textContent = '✓';
      setTimeout(() => {
        btn.textContent = '↻';
        btn.disabled = false;
      }, 1000);
    } else {
      alert(res?.error || 'Sync failed');
      btn.disabled = false;
      btn.textContent = '↻';
    }
  } catch (e) {
    alert('Sync failed: ' + e.message);
    btn.disabled = false;
    btn.textContent = '↻';
  }
});

document.getElementById('accountLink').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('auth.html') });
});

document.getElementById('optionsLink').addEventListener('click', async (e) => {
  e.preventDefault();
  await chrome.runtime.openOptionsPage();
});

// Enter key to unlock
document.getElementById('unlockPwd').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    document.getElementById('unlockBtn').click();
  }
});

// Initial render
render();