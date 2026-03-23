/**
 * app.js
 * ------
 * All frontend logic for the PhishGuard AI detector.
 *
 * Responsibilities
 * ----------------
 * - Handle user input (textarea, file upload, tabs)
 * - Call the Flask backend /predict endpoint
 * - Render the result panel with verdict, confidence bar, and reasons
 * - Manage scan history (fetch from /history, display in drawer)
 * - Toggle dark/light theme
 * - Toast notifications
 *
 * No framework or bundler needed — runs as a plain ES module in any modern browser.
 */

"use strict";

// ── Configuration ──────────────────────────────────────────────────────────
const API_BASE = "http://localhost:5000";   // Change for deployment

// ── DOM references ─────────────────────────────────────────────────────────
const inputText       = document.getElementById("inputText");
const charCount       = document.getElementById("charCount");
const analyseBtn      = document.getElementById("analyseBtn");
const clearBtn        = document.getElementById("clearBtn");
const fileUpload      = document.getElementById("fileUpload");
const themeToggle     = document.getElementById("themeToggle");
const historyToggle   = document.getElementById("historyToggle");
const historyDrawer   = document.getElementById("historyDrawer");
const closeHistoryBtn = document.getElementById("closeHistoryBtn");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const historyList     = document.getElementById("historyList");
const resultsPanel    = document.getElementById("resultsPanel");
const toast           = document.getElementById("toast");
const tabs            = document.querySelectorAll(".tab");

// Results sub-elements
const verdictBanner   = document.getElementById("verdictBanner");
const verdictIcon     = document.getElementById("verdictIcon");
const verdictLabel    = document.getElementById("verdictLabel");
const verdictSub      = document.getElementById("verdictSub");
const confidenceValue = document.getElementById("confidenceValue");
const progressBar     = document.getElementById("progressBar");
const reasonsBlock    = document.getElementById("reasonsBlock");
const reasonsList     = document.getElementById("reasonsList");
const urlFlagsBlock   = document.getElementById("urlFlagsBlock");
const urlFlagsList    = document.getElementById("urlFlagsList");
const inputTypeEl     = document.getElementById("inputType");
const scanTimeEl      = document.getElementById("scanTime");

// ── State ──────────────────────────────────────────────────────────────────
let activeType = "text";   // "text" | "url"
let toastTimer = null;

// ── Verdict config ─────────────────────────────────────────────────────────
const VERDICT_CONFIG = {
  "Phishing": {
    icon:    "🚨",
    cls:     "phishing",
    sub:     "High likelihood of phishing. Do not click links or provide any information.",
    badge:   "badge-phishing",
  },
  "Suspicious": {
    icon:    "⚠️",
    cls:     "suspicious",
    sub:     "Some indicators of phishing detected. Proceed with caution.",
    badge:   "badge-suspicious",
  },
  "Legitimate": {
    icon:    "✅",
    cls:     "legitimate",
    sub:     "No strong phishing indicators detected. Always stay vigilant.",
    badge:   "badge-legitimate",
  },
};

// ── Tab switching ──────────────────────────────────────────────────────────
tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    tabs.forEach(t => { t.classList.remove("active"); t.setAttribute("aria-selected", "false"); });
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    activeType = tab.dataset.type;

    if (activeType === "url") {
      inputText.placeholder = "Paste a URL to analyse (e.g. https://suspicious-domain.tk/login)…";
      inputText.rows = 3;
    } else {
      inputText.placeholder = "Paste your email body or suspicious message here…";
      inputText.rows = 8;
    }
  });
});

// ── Char counter ───────────────────────────────────────────────────────────
inputText.addEventListener("input", () => {
  charCount.textContent = inputText.value.length.toLocaleString();
});

// ── Clear ──────────────────────────────────────────────────────────────────
clearBtn.addEventListener("click", () => {
  inputText.value = "";
  charCount.textContent = "0";
  resultsPanel.hidden = true;
});

// ── File upload ────────────────────────────────────────────────────────────
fileUpload.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (!file.name.endsWith(".txt")) { showToast("⚠️ Please upload a .txt file."); return; }

  const reader = new FileReader();
  reader.onload = (ev) => {
    inputText.value = ev.target.result;
    charCount.textContent = inputText.value.length.toLocaleString();
    showToast("📁 File loaded.");
  };
  reader.readAsText(file);
  // Reset so the same file can be re-uploaded
  e.target.value = "";
});

// ── Analyse ────────────────────────────────────────────────────────────────
analyseBtn.addEventListener("click", runAnalysis);

inputText.addEventListener("keydown", (e) => {
  // Ctrl/Cmd + Enter triggers analysis
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runAnalysis();
});

async function runAnalysis() {
  const text = inputText.value.trim();
  if (!text) { showToast("✏️ Please enter some text or a URL first."); return; }

  // Loading state
  setLoading(true);
  resultsPanel.hidden = true;

  try {
    const response = await fetch(`${API_BASE}/predict`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ text }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Server error: ${response.status}`);
    }

    const data = await response.json();
    renderResult(data);
    resultsPanel.hidden = false;
    resultsPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });

  } catch (err) {
    console.error("Analysis error:", err);
    showToast(`❌ ${err.message}. Is the backend running?`);
  } finally {
    setLoading(false);
  }
}

// ── Render result ──────────────────────────────────────────────────────────
function renderResult(data) {
  const config = VERDICT_CONFIG[data.label] || VERDICT_CONFIG["Suspicious"];
  const pct    = Math.round(data.confidence * 100);

  // Verdict banner
  verdictBanner.className = `verdict-banner ${config.cls}`;
  verdictIcon.textContent  = config.icon;
  verdictLabel.textContent = data.label;
  verdictSub.textContent   = config.sub;

  // Confidence bar
  confidenceValue.textContent = `${pct}%`;
  progressBar.style.width     = `${pct}%`;
  progressBar.className       = `progress-bar ${config.cls}`;

  // Text reasons
  if (data.reasons && data.reasons.length > 0) {
    reasonsList.innerHTML = data.reasons
      .map(r => `<li>${escapeHtml(r)}</li>`)
      .join("");
    reasonsBlock.hidden = false;
  } else {
    reasonsBlock.hidden = true;
  }

  // URL-specific flags
  if (data.url_flags && data.url_flags.length > 0) {
    urlFlagsList.innerHTML = data.url_flags
      .map(f => `<li>${escapeHtml(f)}</li>`)
      .join("");
    urlFlagsBlock.hidden = false;
  } else {
    urlFlagsBlock.hidden = true;
  }

  // Scan meta
  inputTypeEl.textContent = data.input_type === "url" ? "🔗 URL" : "📧 Text";
  scanTimeEl.textContent  = formatTime(data.timestamp);
}

// ── Loading state ──────────────────────────────────────────────────────────
function setLoading(loading) {
  analyseBtn.disabled = loading;
  analyseBtn.querySelector(".btn-text").textContent   = loading ? "Analysing…" : "Analyse";
  analyseBtn.querySelector(".btn-spinner").classList.toggle("hidden", !loading);
}

// ── History ────────────────────────────────────────────────────────────────
historyToggle.addEventListener("click", () => {
  historyDrawer.hidden = false;
  loadHistory();
});
closeHistoryBtn.addEventListener("click", () => { historyDrawer.hidden = true; });

clearHistoryBtn.addEventListener("click", async () => {
  try {
    await fetch(`${API_BASE}/history`, { method: "DELETE" });
    historyList.innerHTML = `<p class="empty-state">No scans yet.</p>`;
    showToast("🗑 History cleared.");
  } catch {
    showToast("❌ Could not clear history.");
  }
});

async function loadHistory() {
  try {
    const res  = await fetch(`${API_BASE}/history?limit=20`);
    const data = await res.json();

    if (!data.history || data.history.length === 0) {
      historyList.innerHTML = `<p class="empty-state">No scans yet.</p>`;
      return;
    }

    historyList.innerHTML = data.history.map(item => {
      const cfg = VERDICT_CONFIG[item.label] || VERDICT_CONFIG["Suspicious"];
      return `
        <div class="history-item" data-text="${escapeAttr(item.input)}">
          <div class="history-item-label">
            <span class="${cfg.badge}">${cfg.icon} ${item.label}</span>
            <span>${Math.round(item.confidence * 100)}%</span>
          </div>
          <div class="history-item-text">${escapeHtml(item.input)}</div>
          <div class="history-item-time">${formatTime(item.timestamp)}</div>
        </div>
      `;
    }).join("");

    // Click to re-populate the input
    historyList.querySelectorAll(".history-item").forEach(el => {
      el.addEventListener("click", () => {
        inputText.value = el.dataset.text;
        charCount.textContent = inputText.value.length.toLocaleString();
        historyDrawer.hidden = true;
      });
    });

  } catch {
    historyList.innerHTML = `<p class="empty-state">Could not load history.</p>`;
  }
}

// ── Theme toggle ───────────────────────────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  themeToggle.textContent = theme === "dark" ? "🌙" : "☀️";
  localStorage.setItem("pg-theme", theme);
}

themeToggle.addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme");
  applyTheme(current === "dark" ? "light" : "dark");
});

// Load saved theme preference
applyTheme(localStorage.getItem("pg-theme") || "dark");

// ── Toast ──────────────────────────────────────────────────────────────────
function showToast(message, duration = 3000) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, duration);
}

// ── Utilities ──────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(str) {
  return String(str).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch { return ""; }
}
