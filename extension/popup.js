async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || '';
}

function setStatus(text) {
  document.getElementById('status').textContent = text;
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

function hostFromUrl(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

async function autofillToTab(tabId, username, password) {
  // Send a message to content script to fill
  await chrome.tabs.sendMessage(tabId, { type: 'PM_AUTOFILL', username, password });
}

async function render() {
  const st = await getStatus();
  const url = await getActiveTabUrl();
  document.getElementById('site').textContent = hostFromUrl(url) || '(unknown)';

  const lockedView = document.getElementById('lockedView');
  const unlockedView = document.getElementById('unlockedView');

  if (!st?.unlocked) {
    setStatus('Locked');
    lockedView.style.display = 'block';
    unlockedView.style.display = 'none';
  } else {
    setStatus('Unlocked');
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
          <div><strong>${c.username}</strong></div>
          <div style="display:flex; gap:6px; margin-top:6px; flex-wrap: wrap;">
            <button class="fill">Autofill</button>
            <button class="del" style="color:#b00;">Delete</button>
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
          await deleteCredential(url, c.username);
          await render();
        });
        list.appendChild(div);
      }
    } else {
      noCreds.style.display = 'block';
    }
  }
}

function wireEvents() {
  document.getElementById('unlockBtn').addEventListener('click', async () => {
    const pwd = document.getElementById('unlockPwd').value;
    if (!pwd) return;
    const res = await unlock(pwd);
    if (!res?.ok) alert(res.error || 'Unlock failed');
    await render();
  });

  document.getElementById('lockBtn').addEventListener('click', async () => {
    await lock();
    await render();
  });

  document.getElementById('optionsLink').addEventListener('click', async (e) => {
    e.preventDefault();
    await chrome.runtime.openOptionsPage();
  });
}

wireEvents();
render();
