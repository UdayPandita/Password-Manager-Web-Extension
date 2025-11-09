(async () => {
  const phraseEl = document.getElementById('phrase');
  const savedBtn = document.getElementById('savedBtn');
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_GET_MNEMONIC' });
    if (!resp.ok) throw new Error(resp.error || 'No phrase');
    const mnemonic = resp.mnemonic;
    if (!mnemonic) {
      phraseEl.textContent = 'No phrase available. Please restart signup.';
      savedBtn.disabled = true;
    } else {
      phraseEl.textContent = mnemonic;
    }
  } catch (e) {
    phraseEl.textContent = 'Error generating phrase';
    savedBtn.disabled = true;
  }

  savedBtn.addEventListener('click', () => {
    // Go to verification page
    window.location.href = 'mnemonic-verify.html';
  });
})();
