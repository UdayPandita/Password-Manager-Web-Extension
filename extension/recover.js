document.getElementById('recoverForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const mnemonic = document.getElementById('mnemonic').value.trim();
  const newpw = document.getElementById('newpw').value;
  const confirm = document.getElementById('confirm').value;
  const msg = document.getElementById('msg');
  msg.textContent = '';

  if (newpw.length < 8) {
    msg.style.color = '#c00';
    msg.textContent = 'New password must be at least 8 characters';
    return;
  }
  if (newpw !== confirm) {
    msg.style.color = '#c00';
    msg.textContent = 'Passwords do not match';
    return;
  }

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_RECOVER_ACCOUNT', mnemonic, newPassword: newpw });
    if (resp.ok) {
      msg.style.color = 'green';
      msg.textContent = 'Recovery complete. Please sign in with your new password.';
      setTimeout(() => window.location.href = 'auth.html', 1200);
    } else {
      throw new Error(resp.error || 'Recovery failed');
    }
  } catch (e) {
    msg.style.color = '#c00';
    msg.textContent = e.message;
  }
});
