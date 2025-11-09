document.getElementById('verifyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('mnemonicInput').value.trim();
  const msg = document.getElementById('msg');
  msg.textContent = '';
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_VERIFY_MNEMONIC', mnemonic: input });
    if (resp.ok) {
      msg.style.color = 'green';
      msg.textContent = 'Account created and verified. You can now use the extension.';
      setTimeout(() => window.close(), 1200);
    } else {
      throw new Error(resp.error || 'Verification failed');
    }
  } catch (e) {
    msg.style.color = '#c00';
    msg.textContent = e.message;
  }
});
