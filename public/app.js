const tabs = document.querySelectorAll('.tab');
const input = document.querySelector('#content-input');
const inputHint = document.querySelector('#input-hint');
const analyzeButton = document.querySelector('#analyze-button');
const scannerMessage = document.querySelector('#scanner-message');
const resultContainer = document.querySelector('#result-container');
const heroScoreRing = document.querySelector('#hero-score-ring');

const statTotal = document.querySelector('#stat-total');
const statHigh = document.querySelector('#stat-high');
const statMed = document.querySelector('#stat-med');
const statLow = document.querySelector('#stat-low');
const historyTbody = document.querySelector('#history-tbody');

const apiOrigin = window.location.port === '3000' || window.location.port === '' ? window.location.origin : 'http://localhost:3000';

const demos = [
  ['Message', 'Hi, dinner is at 7pm. See you there!'],
  ['Message', 'Urgent: your bank account will be suspended. Verify your OTP and PIN immediately.'],
  ['Message', 'Congratulations, you are selected for a work-from-home job. Pay a registration fee today.'],
  ['URL', 'https://paypal.secure-login.example.com/account/verify'],
  ['URL', 'https://example.com'],
  ['URL', 'http://bit.ly/secure-banking-portal-verify']
];

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[char]));
}

function getActiveType() {
  const activeTab = document.querySelector('.tab.is-active');
  return activeTab && activeTab.dataset.type === 'URL' ? 'url' : 'message';
}

function validate(type, value) {
  if (!value.trim()) return 'Add a message or URL to prepare an analysis.';
  if (type === 'url') {
    try {
      const url = new URL(value.trim());
      if (!/^https?:$/.test(url.protocol) || !url.hostname || /[\s<>"{}|\\^`]/.test(value)) {
        throw new Error();
      }
    } catch {
      return 'URL mode requires a complete, valid HTTP or HTTPS URL.';
    }
  }
  return '';
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('phisguard-theme', theme);
  const dark = theme === 'dark';
  document.querySelector('#theme-icon').textContent = dark ? '☀' : '☾';
  document.querySelector('#theme-toggle').setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
}

// Initialize theme from storage or prefers-color-scheme
const savedTheme = localStorage.getItem('phisguard-theme') || 
  (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
setTheme(savedTheme);

document.querySelector('#theme-toggle').addEventListener('click', () => {
  setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});

const textInputWrapper = document.querySelector('#text-input-wrapper');
const qrInputWrapper = document.querySelector('#qr-input-wrapper');
const qrFileInput = document.querySelector('#qr-file-input');
const qrBrowseBtn = document.querySelector('#qr-browse-btn');
const qrDropzone = document.querySelector('#qr-dropzone');
const qrCanvas = document.querySelector('#qr-canvas');
const qrPreviewContainer = document.querySelector('#qr-preview-container');
const qrStatus = document.querySelector('#qr-status');

tabs.forEach((tab) => {
  tab.addEventListener('click', () => {
    tabs.forEach((item) => {
      item.classList.remove('is-active');
      item.setAttribute('aria-selected', 'false');
    });
    tab.classList.add('is-active');
    tab.setAttribute('aria-selected', 'true');
    
    if (tab.dataset.type === 'QR Code') {
      textInputWrapper.style.display = 'none';
      qrInputWrapper.style.display = 'block';
      inputHint.textContent = 'Upload or drop a QR code image to decode and screen for quishing & fraudulent links.';
    } else {
      textInputWrapper.style.display = 'block';
      qrInputWrapper.style.display = 'none';
      input.placeholder = `Paste a suspicious ${tab.dataset.type.toLowerCase()} here...`;
      inputHint.textContent = tab.dataset.type === 'URL' 
        ? 'URL mode inspects address structure, subdomains, lookalikes, risky TLDs and ports without fetching remote servers.' 
        : 'Message mode checks message language, urgency indicators, and credential requests.';
    }
    resultContainer.replaceChildren();
    scannerMessage.textContent = '';
  });
});

if (qrBrowseBtn && qrFileInput) {
  qrBrowseBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    qrFileInput.click();
  });
  qrDropzone.addEventListener('click', () => qrFileInput.click());

  qrDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    qrDropzone.classList.add('dragover');
  });

  qrDropzone.addEventListener('dragleave', () => qrDropzone.classList.remove('dragover'));

  qrDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    qrDropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleQrFile(e.dataTransfer.files[0]);
    }
  });

  qrFileInput.addEventListener('change', () => {
    if (qrFileInput.files && qrFileInput.files[0]) {
      handleQrFile(qrFileInput.files[0]);
    }
  });
}

function handleQrFile(file) {
  if (!file.type.startsWith('image/')) {
    scannerMessage.className = 'scanner-message is-error';
    scannerMessage.textContent = 'Please select a valid image file (PNG, JPG, WebP).';
    return;
  }
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      const ctx = qrCanvas.getContext('2d');
      qrCanvas.width = img.width;
      qrCanvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      qrPreviewContainer.style.display = 'block';

      if (typeof jsQR !== 'undefined') {
        const imageData = ctx.getImageData(0, 0, img.width, img.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'dontInvert',
        });
        if (code && code.data) {
          qrStatus.textContent = `Decoded: ${code.data}`;
          input.value = code.data;
          
          // Switch to URL or Message mode automatically based on decoded payload
          const isUrl = /^https?:\/\//i.test(code.data.trim());
          tabs.forEach((t) => {
            const active = isUrl ? t.dataset.type === 'URL' : t.dataset.type === 'SMS message';
            t.classList.toggle('is-active', active);
            t.setAttribute('aria-selected', String(active));
          });
          textInputWrapper.style.display = 'block';
          qrInputWrapper.style.display = 'none';
          
          analyzeButton.click();
        } else {
          qrStatus.textContent = 'No QR code could be found in this image. Try a sharper image.';
          scannerMessage.className = 'scanner-message is-error';
          scannerMessage.textContent = 'No QR code detected in the uploaded image.';
        }
      } else {
        qrStatus.textContent = 'Decoded preview loaded.';
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

let cachedScans = [];

async function fetchDashboard() {
  try {
    const res = await fetch(`${apiOrigin}/api/dashboard`);
    if (!res.ok) return;
    const data = await res.json();
    if (statTotal) statTotal.textContent = data.totalScans || 0;
    if (statHigh) statHigh.textContent = (data.riskCounts && data.riskCounts.High) || 0;
    if (statMed) statMed.textContent = (data.riskCounts && data.riskCounts.Medium) || 0;
    if (statLow) statLow.textContent = (data.riskCounts && data.riskCounts.Low) || 0;

    if (data.recentScans) {
      cachedScans = data.recentScans;
    }

    if (historyTbody && data.recentScans && data.recentScans.length > 0) {
      historyTbody.innerHTML = data.recentScans.map((scan) => {
        const time = new Date(scan.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const riskColor = scan.riskLevel === 'High' ? 'var(--error)' : scan.riskLevel === 'Medium' ? 'var(--warning)' : 'var(--success)';
        return `
          <tr>
            <td class="mono ink">${escapeHtml(scan.type.toUpperCase())}</td>
            <td>${escapeHtml(scan.scamCategory)}</td>
            <td><strong style="color: ${riskColor}">${escapeHtml(scan.riskLevel)}</strong></td>
            <td class="mono">${scan.riskScore}/100</td>
            <td class="mono">${time}</td>
          </tr>
        `;
      }).join('');
    }
  } catch (err) {
    console.debug('Dashboard fetch suppressed:', err);
  }
}

const btnExportCsv = document.querySelector('#btn-export-csv');
const btnExportJson = document.querySelector('#btn-export-json');

if (btnExportCsv) {
  btnExportCsv.addEventListener('click', () => {
    if (!cachedScans || cachedScans.length === 0) {
      alert('No scans in current session to export yet.');
      return;
    }
    const headers = ['ID', 'Type', 'Category', 'RiskLevel', 'RiskScore', 'Timestamp'];
    const rows = cachedScans.map((s) => [
      `"${s.id || ''}"`,
      `"${s.type || ''}"`,
      `"${(s.scamCategory || '').replace(/"/g, '""')}"`,
      `"${s.riskLevel || ''}"`,
      s.riskScore ?? 0,
      `"${s.createdAt || ''}"`
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishguard-telemetry-${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  });
}

if (btnExportJson) {
  btnExportJson.addEventListener('click', () => {
    if (!cachedScans || cachedScans.length === 0) {
      alert('No scans in current session to export yet.');
      return;
    }
    const blob = new Blob([JSON.stringify(cachedScans, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishguard-telemetry-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  });
}

analyzeButton.addEventListener('click', async () => {
  const selectedType = getActiveType();
  const validationError = validate(selectedType, input.value);
  if (validationError) {
    scannerMessage.className = 'scanner-message is-error';
    scannerMessage.textContent = validationError;
    input.focus();
    return;
  }

  analyzeButton.disabled = true;
  scannerMessage.className = 'scanner-message';
  scannerMessage.textContent = 'Analyzing content indicators…';
  resultContainer.replaceChildren();

  try {
    const response = await fetch(`${apiOrigin}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: selectedType, content: input.value })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Analysis failed.');

    const riskClass = result.riskLevel.toLowerCase();
    
    // Update hero signal ring
    if (heroScoreRing) {
      heroScoreRing.textContent = result.riskScore;
      heroScoreRing.style.color = riskClass === 'high' ? 'var(--error)' : riskClass === 'medium' ? 'var(--warning)' : 'var(--success)';
      heroScoreRing.style.borderColor = heroScoreRing.style.color;
    }

    resultContainer.innerHTML = `
      <article class="analysis-result risk-${riskClass}">
        <div class="result-heading">
          <div class="result-badge">
            <span>Assessment:</span>
            <span class="risk-tag">${escapeHtml(result.riskLevel)} Risk</span>
          </div>
          <span class="result-score">Risk Score: ${result.riskScore} / 100</span>
        </div>

        <div class="result-meta">
          <div class="result-meta-item">Category: <strong>${escapeHtml(result.scamCategory)}</strong></div>
          <div class="result-meta-item">Engine: <strong>Rule-based Signals ${result.modelPrediction?.available !== false && result.modelPrediction?.label ? '+ DistilBERT' : ''}</strong></div>
        </div>

        <div class="result-columns">
          <div>
            <div class="result-box-title">
              <span aria-hidden="true">⚠</span> Indicators Detected
            </div>
            <ul>
              ${result.detectedIndicators.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}
            </ul>
          </div>
          <div>
            <div class="result-box-title">
              <span aria-hidden="true">✓</span> Recommended Safe Actions
            </div>
            <ul>
              ${result.recommendedActions.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}
            </ul>
          </div>
        </div>

        <p class="result-note">
          Screening assessment only. PhishGuard inspects syntactical patterns and natural language structures. Never submit personal credentials or private keys.
        </p>
      </article>
    `;

    scannerMessage.textContent = 'Analysis complete.';
    fetchDashboard();
  } catch (error) {
    scannerMessage.className = 'scanner-message is-error';
    scannerMessage.textContent = error.message;
  } finally {
    analyzeButton.disabled = false;
  }
});

document.querySelectorAll('.demo-button').forEach((button) => {
  button.addEventListener('click', () => {
    const [kind, value] = demos[Number(button.dataset.demo)];
    tabs.forEach((tab) => {
      const selected = (kind === 'URL' && tab.dataset.type === 'URL') || (kind === 'Message' && tab.dataset.type !== 'URL');
      tab.classList.toggle('is-active', selected);
      tab.setAttribute('aria-selected', String(selected));
    });
    input.value = value;
    analyzeButton.click();
    input.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
});

// Initial dashboard poll
fetchDashboard();
