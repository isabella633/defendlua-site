function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {});
}

const form = document.getElementById('protectForm');
if (form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const codeEl = document.getElementById('codeInput');
    const code = (codeEl?.value || '').trim();
    if (!code) return;

    const formData = new FormData();
    formData.append('code', code);

    try {
      const res = await fetch('/protect', { method: 'POST', body: formData });
      const data = await res.json();
      if (data.success) {
        const result = document.getElementById('result');
        const protectedUrl = document.getElementById('protectedUrl');
        const loadstringUrl = document.getElementById('loadstringUrl');
        protectedUrl.value = data.protected_url;
        loadstringUrl.value = `loadstring(game:HttpGet('${data.loadstring_url}'))()`;
        result.classList.remove('d-none');
      } else {
        alert('Error: ' + (data.error || 'unknown error'));
      }
    } catch (err) {
      alert('Network error');
    }
  });
}

async function obfuscateCode() {
  const codeEl = document.getElementById('codeInput');
  const code = (codeEl?.value || '').trim();
  if (!code) return alert('Enter code first');

  const fd = new FormData();
  fd.append('code', code);
  try {
    const res = await fetch('/obfuscate', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.success) {
      const obf = data.obfuscated_code;
      copyToClipboard(obf);
      alert('Obfuscated code copied to clipboard');
    } else {
      alert('Error: ' + (data.error || 'unknown error'));
    }
  } catch (e) {
    alert('Network error');
  }
}

function copyLoadstring() {
  const el = document.getElementById('loadstringUrl');
  if (el) copyToClipboard(el.value);
}
