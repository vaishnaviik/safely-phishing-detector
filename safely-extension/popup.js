// ================= CONFIG =================
const CONFIG = {
  STREAMLIT_URL: "http://localhost:8501",
  ANALYZE_ENDPOINT: "http://localhost:8501/analyze",
  AUTO_SCAN_INTERVAL: 5000,
  USE_API_MODE: false
};

// ================= STATE =================
let autoScanInterval = null;
let lastScanResult = null;

// ================= SAFE STORAGE HELPERS =================
function safeStorageGet(keys) {
  return new Promise((resolve) => {
    if (chrome?.storage?.local) {
      chrome.storage.local.get(keys, resolve);
    } else {
      resolve({});
    }
  });
}

function safeStorageSet(obj) {
  if (chrome?.storage?.local) {
    chrome.storage.local.set(obj);
  }
}

// ================= WAIT FOR DOM =================
document.addEventListener("DOMContentLoaded", async () => {
  const elements = {
    scanBtn: document.getElementById("scanBtn"),
    loading: document.getElementById("loading"),
    results: document.getElementById("results"),
    riskScore: document.getElementById("riskScore"),
    threatLevel: document.getElementById("threatLevel"),
    warningMessage: document.getElementById("warningMessage"),
    timestamp: document.getElementById("timestamp"),
    autoScanToggle: document.getElementById("autoScanToggle")
  };

  // ===== SCAN BUTTON =====
  elements.scanBtn.addEventListener("click", () => handleScanClick(elements));

  // ===== AUTO SCAN TOGGLE =====
  elements.autoScanToggle.addEventListener("change", (e) => {
    const enabled = e.target.checked;
    safeStorageSet({ autoScanEnabled: enabled });

    if (enabled) startAutoScan(elements);
    else stopAutoScan();
  });

  // ===== RESTORE AUTO-SCAN STATE =====
  const stored = await safeStorageGet(["autoScanEnabled"]);
  if (stored.autoScanEnabled) {
    elements.autoScanToggle.checked = true;
    startAutoScan(elements);
  }

  // ===== LOAD LAST RESULT =====
  const last = await safeStorageGet(["lastScanResult"]);
  if (last.lastScanResult) {
    displayResults(elements, last.lastScanResult);
  }
});

// ================= MAIN SCAN =================
async function handleScanClick(elements) {
  try {
    elements.scanBtn.disabled = true;
    showLoading(elements);

    const pageContent = await extractPageContent();
    if (!pageContent) throw new Error("Failed to read page");

    const result = await analyzeContent(pageContent);

    displayResults(elements, result);
    saveLastScanResult(result);

  } catch (err) {
    console.error("Scan error:", err);
    showError(elements, err.message);
  } finally {
    elements.scanBtn.disabled = false;
  }
}

// ================= EXTRACT PAGE =================
async function extractPageContent() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab");

  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => ({
      text: document.body.innerText,
      url: location.href,
      title: document.title
    })
  });

  return results?.[0]?.result;
}

// ================= ANALYSIS =================
async function analyzeContent(pageContent) {
  if (CONFIG.USE_API_MODE) return analyzeViaAPI(pageContent);
  return simulateAnalysis(pageContent);
}

// ===== DEMO HEURISTIC ANALYSIS =====
function simulateAnalysis({ text, url, title }) {
  let riskScore = 0;
  const reasons = [];

  const lowerText = text.toLowerCase();
  const lowerUrl = url.toLowerCase();

  const suspiciousKeywords = [
    "verify your account",
    "confirm identity",
    "urgent action required",
    "click here immediately",
    "reset password",
    "update payment",
    "unusual activity",
    "claim reward"
  ];

  suspiciousKeywords.forEach(k => {
    if (lowerText.includes(k)) {
      riskScore += 15;
      reasons.push(`Suspicious phrase: "${k}"`);
    }
  });

  if (/\d+\.\d+\.\d+\.\d+/.test(url)) {
    riskScore += 25;
    reasons.push("IP address in URL");
  }

  if (lowerUrl.includes("login") || lowerUrl.includes("signin")) {
    riskScore += 10;
    reasons.push("Login keyword in URL");
  }

  riskScore = Math.min(riskScore, 100);

  let threat = "Low";
  if (riskScore >= 70) threat = "High";
  else if (riskScore >= 40) threat = "Medium";

  return {
    risk_score: riskScore,
    threat_level: threat,
    warning:
      threat === "High"
        ? "⚠️ High phishing risk detected."
        : threat === "Medium"
        ? "⚠️ Suspicious page. Be careful."
        : "✓ Page appears safe.",
    url,
    title,
    timestamp: new Date().toISOString()
  };
}

// ===== OPTIONAL API MODE =====
async function analyzeViaAPI(pageContent) {
  try {
    const res = await fetch(CONFIG.ANALYZE_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pageContent)
    });

    const data = await res.json();
    return { ...data, timestamp: new Date().toISOString() };

  } catch {
    return simulateAnalysis(pageContent);
  }
}

// ================= UI =================
function showLoading(el) {
  el.results.classList.add("hidden");
  el.loading.classList.remove("hidden");
}

function displayResults(el, r) {
  el.loading.classList.add("hidden");
  el.results.classList.remove("hidden");

  el.riskScore.textContent = r.risk_score;

  const badge = el.threatLevel.querySelector(".threat-badge");
  badge.textContent = r.threat_level;
  badge.className = "threat-badge " + r.threat_level.toLowerCase();

  el.warningMessage.innerHTML = `<p>${r.warning}</p>`;
  el.timestamp.textContent =
    "Last scanned: " + new Date(r.timestamp).toLocaleTimeString();
}

function showError(el, msg) {
  el.loading.classList.add("hidden");
  el.results.classList.remove("hidden");

  el.riskScore.textContent = "!";
  el.warningMessage.innerHTML = `⚠️ ${msg}`;
  el.timestamp.textContent = "Scan failed";
}

// ================= AUTO SCAN =================
function startAutoScan(elements) {
  stopAutoScan();
  handleScanClick(elements);

  autoScanInterval = setInterval(
    () => handleScanClick(elements),
    CONFIG.AUTO_SCAN_INTERVAL
  );
}

function stopAutoScan() {
  if (autoScanInterval) clearInterval(autoScanInterval);
  autoScanInterval = null;
}

// ================= STORAGE =================
function saveLastScanResult(result) {
  lastScanResult = result;
  safeStorageSet({ lastScanResult: result });
}

// ================= CLEANUP =================
window.addEventListener("unload", stopAutoScan);
