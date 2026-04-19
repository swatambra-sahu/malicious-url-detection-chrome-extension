// popup.js — ThreatShield Chrome Extension

const API_URL = 'https://swatambra.pythonanywhere.com/predict';
const TIMEOUT_MS = 10000;
const MAX_HISTORY = 5;

// Category display mapping (matches web UI)
const categoryDisplay = {
  benign:      { label: 'Safe',        color: '#2ed573', bg: 'rgba(46,213,115,0.08)', icon: '✓', msg: 'No threats detected. This URL appears to be safe.' },
  phishing:    { label: 'Phishing',    color: '#ff4757', bg: 'rgba(255,71,87,0.08)',   icon: '⚠', msg: 'This URL has been classified as a phishing attempt.' },
  malware:     { label: 'Malware',     color: '#ff6348', bg: 'rgba(255,99,72,0.08)',   icon: '☠', msg: 'This URL has been flagged for hosting malware.' },
  defacement:  { label: 'Defacement',  color: '#ffa502', bg: 'rgba(255,165,2,0.08)',   icon: '⚡', msg: 'This URL appears to be a defaced website.' },
};

function getDisplay(cat) {
  return categoryDisplay[cat] || categoryDisplay.phishing;
}

// ─── Ensure URL has a scheme ───
function ensureScheme(url) {
  if (!/^https?:\/\//i.test(url)) {
    return 'https://' + url;
  }
  return url;
}

// ─── UI Helpers ───
function setScanning(active) {
  const btn = document.getElementById('predictButton');
  const btnText = document.getElementById('btnText');
  const scanning = document.getElementById('scanning');

  if (active) {
    btn.disabled = true;
    btnText.textContent = 'Scanning...';
    scanning.classList.add('active');
  } else {
    btn.disabled = false;
    btnText.textContent = 'Scan URL';
    scanning.classList.remove('active');
  }
}

// ─── Render result card ───
function renderResult(data, url) {
  const el = document.getElementById('result');
  el.innerHTML = '';

  const isSafe = data.result_str === 'URL IS SAFE!';
  const cat = data.predicted_class || (isSafe ? 'benign' : 'phishing');
  const d = getDisplay(cat);
  const conf = data.confidence != null ? Math.round(data.confidence) : '—';

  el.innerHTML = `
    <div class="result-card">
      <div class="result-header">
        <div class="result-verdict">
          <div class="result-icon" style="background:${d.bg}; color:${d.color};">${d.icon}</div>
          <div>
            <div class="result-title" style="color:${d.color};">${d.label}</div>
            <div class="result-subtitle">${data.result_str}</div>
          </div>
        </div>
        <div class="score-badge" style="background:${d.bg}; color:${d.color};">${conf}</div>
      </div>
      <div class="result-url" title="${url}">${url}</div>
      <div class="result-category">
        <span class="result-category-label">Category</span>
        <span class="result-category-badge" style="background:${d.bg}; color:${d.color};">${d.label}</span>
      </div>
      <div class="result-message" style="background:${d.bg}; color:${d.color};">
        ${d.icon} ${d.msg}
      </div>
    </div>`;
}

// ─── Render error card ───
function renderError(title, detail, hint) {
  const el = document.getElementById('result');
  el.innerHTML = `
    <div class="error-card">
      <div class="error-header">
        <div class="error-icon">⚠</div>
        <div>
          <div class="error-title">${title}</div>
          <div class="error-subtitle">${detail}</div>
        </div>
      </div>
      <div class="error-body">
        <p>${hint}</p>
        <p>Ensure Flask is running on http://127.0.0.1:5000</p>
      </div>
    </div>`;
}

// ─── History (chrome.storage.local) ───
async function loadHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.get({ scanHistory: [] }, (res) => {
      resolve(res.scanHistory || []);
    });
  });
}

async function addHistory(entry) {
  const history = await loadHistory();
  history.unshift(entry);
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  return new Promise((resolve) => {
    chrome.storage.local.set({ scanHistory: history }, resolve);
  });
}

function renderHistory(history) {
  const section = document.getElementById('historySection');
  const list = document.getElementById('historyList');

  if (!history || history.length === 0) {
    section.classList.remove('active');
    return;
  }

  section.classList.add('active');
  list.innerHTML = '';

  history.forEach((item) => {
    const d = getDisplay(item.category);
    const btn = document.createElement('button');
    btn.className = 'history-item';
    btn.innerHTML = `
      <span class="history-dot" style="background:${d.color};"></span>
      <span class="history-url">${item.url}</span>
      <span class="history-score" style="background:${d.bg}; color:${d.color};">${item.confidence}%</span>`;
    btn.addEventListener('click', () => {
      document.getElementById('urlInput').value = item.url;
      scanUrl();
    });
    list.appendChild(btn);
  });
}

// ─── Main scan function ───
async function scanUrl() {
  const input = document.getElementById('urlInput');
  let url = input.value.trim();

  if (!url) {
    renderError('No URL', 'empty-input', 'Please enter a URL to scan.');
    return;
  }

  url = ensureScheme(url);
  input.value = url;

  setScanning(true);
  document.getElementById('result').innerHTML = '';

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw { type: 'server', status: response.status };
    }

    const data = await response.json();
    renderResult(data, url);

    // Save to history
    const isSafe = data.result_str === 'URL IS SAFE!';
    const cat = data.predicted_class || (isSafe ? 'benign' : 'phishing');
    const conf = data.confidence != null ? Math.round(data.confidence) : 0;
    await addHistory({ url, category: cat, confidence: conf });

    const history = await loadHistory();
    renderHistory(history);

  } catch (err) {
    clearTimeout(timeout);

    if (err.name === 'AbortError') {
      renderError('Timeout', 'request-aborted', 'The scan timed out after 10 seconds. The server may be starting up.');
    } else if (err.type === 'server') {
      renderError('Server Error', `HTTP ${err.status}`, `The server returned an error (${err.status}). Check server logs.`);
    } else if (err instanceof TypeError) {
      renderError('Connection Failed', 'network-error', 'Could not reach the server. Is Flask running?');
    } else {
      renderError('Unknown Error', err.message || 'unexpected', 'Something went wrong. Please try again.');
    }
  } finally {
    setScanning(false);
  }
}

// ─── Init ───
document.addEventListener('DOMContentLoaded', async () => {
  const btn = document.getElementById('predictButton');
  const input = document.getElementById('urlInput');

  // Click handler
  btn.addEventListener('click', scanUrl);

  // Enter key
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') scanUrl();
  });

  // Auto-detect current tab URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:\/\//.test(tab.url)) {
      input.value = tab.url;
    }
  } catch (_) { /* ignore if tabs API unavailable */ }

  // Load history
  const history = await loadHistory();
  renderHistory(history);
});