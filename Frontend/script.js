// ═══════════════════════════════════════════════════════════════════
// ZaifSecurity — Frontend Script v2.1
// Handles: scan tabs, API calls, result display, animations
// ═══════════════════════════════════════════════════════════════════

const API_BASE = "http://127.0.0.1:8000";
let activeTab  = "text";   // current scan type

// ──────────────────────────────────────────────────────────────────
// DOM Ready
// ──────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {

    // 1 — Smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(a => {
        a.addEventListener("click", e => {
            e.preventDefault();
            const t = document.querySelector(a.getAttribute("href"));
            if (t) t.scrollIntoView({ behavior: "smooth", block: "start" });
        });
    });

    // 2 — Tool card flip
    document.querySelectorAll(".tool-card").forEach(card => {
        card.addEventListener("click", () => {
            const inner = card.querySelector(".card-inner");
            inner.style.transform =
                inner.style.transform === "rotateY(180deg)"
                    ? "rotateY(0deg)"
                    : "rotateY(180deg)";
        });
    });

    // 3 — Scan tabs
    document.querySelectorAll(".scan-tab").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".scan-tab").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".scan-panel").forEach(p => p.classList.remove("active"));
            btn.classList.add("active");
            activeTab = btn.dataset.tab;
            document.getElementById(`panel-${activeTab}`).classList.add("active");
        });
    });

    // 4 — Detail tabs (in results)
    document.querySelectorAll(".detail-tab").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".detail-tab").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".detail-panel").forEach(p => p.classList.remove("active"));
            btn.classList.add("active");
            document.getElementById(`detail-${btn.dataset.detail}`).classList.add("active");
        });
    });

    // 5 — Universal file picker for all upload tabs
    setupUniversalInput("universalInput", [
        {
            labelId: "fileLabel",
            iconClass: "fa-solid fa-file-arrow-up",
            hint: "Drop files here (.txt, .eml, .pdf, .doc, .docx, .apk, .mp3, .wav), or click to browse",
        },
        {
            labelId: "audioLabel",
            iconClass: "fa-solid fa-microphone",
            hint: "Drop .mp3, .wav or .aac file here, or click to browse",
        },
        {
            labelId: "apkLabel",
            iconClass: "fa-brands fa-android",
            hint: "Drop Android APK file here, or click to browse",
        },
    ]);

    // 6 — Analyze button
    document.getElementById("analyzeBtn").addEventListener("click", performAnalysis);

    // 7 — Contact form
    const cf = document.getElementById("contactForm");
    if (cf) {
        cf.addEventListener("submit", e => {
            e.preventDefault();
            const btn = e.target.querySelector("button");
            btn.textContent = "✓ MESSAGE SENT!";
            btn.style.background = "var(--primary-green)";
            btn.style.color = "#000";
            setTimeout(() => {
                btn.textContent = "SEND MESSAGE";
                btn.style.background = "transparent";
                btn.style.color = "var(--primary-red)";
                cf.reset();
            }, 3000);
        });
    }

    // 8 — Scroll animations
    const obs = new IntersectionObserver(entries => {
        entries.forEach(en => {
            if (en.isIntersecting) {
                en.target.style.opacity = "1";
                en.target.style.transform = "translateY(0)";
                obs.unobserve(en.target);
            }
        });
    }, { threshold: 0.1, rootMargin: "0px 0px -50px 0px" });

    document.querySelectorAll(".tool-card, .workflow-step, .about-card").forEach(el => {
        el.style.opacity = "0";
        el.style.transform = "translateY(20px)";
        el.style.transition = "opacity 0.6s ease, transform 0.6s ease";
        obs.observe(el);
    });
});

// ──────────────────────────────────────────────────────────────────
// File label helper
// ──────────────────────────────────────────────────────────────────
function setupUniversalInput(inputId, labelConfigs) {
    const input = document.getElementById(inputId);
    if (!input) return;

    const labels = labelConfigs
        .map(cfg => ({
            ...cfg,
            element: document.getElementById(cfg.labelId),
        }))
        .filter(cfg => cfg.element);

    const resetLabels = () => {
        labels.forEach(({element, iconClass, hint}) => {
            const icon = element.querySelector("i");
            const text = element.querySelector("span");
            if (icon) {
                icon.className = iconClass;
                icon.style.color = "";
            }
            if (text) {
                text.textContent = hint;
                text.style.color = "";
            }
            element.classList.remove("selected-file");
        });
    };

    labels.forEach(cfg => {
        cfg.element.addEventListener("click", event => {
            event.preventDefault();
            input.click();
        });
    });

    input.addEventListener("change", () => {
        const file = input.files?.[0];
        if (file) {
            labels.forEach(({element}) => {
                const icon = element.querySelector("i");
                const text = element.querySelector("span");
                if (icon) {
                    icon.className = "fa-solid fa-check-circle";
                    icon.style.color = "var(--primary-red)";
                }
                if (text) {
                    text.textContent = file.name;
                    text.style.color = "var(--primary-red)";
                }
                element.classList.add("selected-file");
            });
        } else {
            resetLabels();
        }
    });

    resetLabels();
}

// ──────────────────────────────────────────────────────────────────
// Main analysis dispatcher
// ──────────────────────────────────────────────────────────────────
async function performAnalysis() {
    const btn = document.getElementById("analyzeBtn");
    const resultSection = document.getElementById("result");

    const activeInput = getActiveInputValue(activeTab);
    if (!activeInput.valid) {
        showError(`❌ Please provide input for the "${activeTab.toUpperCase()}" tab.`);
        return;
    }

    // Show loading state
    resultSection.classList.remove("hidden");
    resultSection.scrollIntoView({ behavior: "smooth" });
    setLoadingState(btn);

    try {
        let data;
        switch (activeTab) {
            case "text":  data = await analyzeEmail();  break;
            case "url":   data = await analyzeURL();   break;
            case "file":  data = await analyzeFile();  break;
            case "audio": data = await analyzeAudio(); break;
            case "apk":   data = await analyzeAPK();   break;
            default: throw new Error("Unknown analysis tab.");
        }
        if (data) displayResults(data);
    } catch (err) {
        console.error(err);
        showError(`❌ Analysis failed: ${err.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>ANALYZE NOW</span> <i class="fa-solid fa-shield-halved"></i>`;
    }
}

// ──────────────────────────────────────────────────────────────────
// API calls
// ──────────────────────────────────────────────────────────────────
async function analyzeEmail() {
    const text = document.getElementById("textInput").value.trim();
    const res  = await fetchJSON(`${API_BASE}/analyze-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
    });
    return res;
}

async function analyzeURL() {
    const url = document.getElementById("urlInput").value.trim();
    const res = await fetchJSON(`${API_BASE}/analyze-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
    });
    return { ...res, analysis_type: "url" };
}

function getActiveInputValue(tab) {
    switch (tab) {
        case "text": {
            const textarea = document.getElementById("textInput");
            const text = textarea?.value?.trim() || "";
            return { valid: Boolean(text), value: text };
        }
        case "url": {
            const urlInput = document.getElementById("urlInput");
            const url = urlInput?.value?.trim() || "";
            return { valid: Boolean(url), value: url };
        }
        case "file":
        case "audio":
        case "apk": {
            const universalInput = document.getElementById("universalInput");
            const file = universalInput?.files?.[0] || null;
            return { valid: Boolean(file), value: file };
        }
        default:
            return { valid: false, value: null };
    }
}

async function analyzeFile() {
    const universalInput = document.getElementById("universalInput");
    const file = universalInput?.files?.[0];
    if (!file) {
        throw new Error("Please select a file for analysis.");
    }
    const fd = new FormData();
    fd.append("file", file, file.name);
    return fetchJSON(`${API_BASE}/scan-file`, { method: "POST", body: fd });
}

async function analyzeAudio() {
    const universalInput = document.getElementById("universalInput");
    const audioFile = universalInput?.files?.[0];
    if (!audioFile) {
        showError("❌ Please select an audio file for analysis.");
        throw new Error("No audio file selected.");
    }
    const isAudio = /^audio\//i.test(audioFile.type) || /\.(mp3|wav|aac|flac|ogg|m4a)$/i.test(audioFile.name);
    if (!isAudio) {
        showError("❌ Selected file is not a valid audio file. Please choose .mp3, .wav, or .aac.");
        throw new Error("Selected file is not audio.");
    }
    const fd = new FormData();
    fd.append("file", audioFile, audioFile.name);
    return fetchJSON(`${API_BASE}/scan-audio`, { method: "POST", body: fd });
}

async function analyzeAPK() {
    const universalInput = document.getElementById("universalInput");
    const apkFile = universalInput?.files?.[0];
    if (!apkFile) {
        showError("❌ Please select an APK file for analysis.");
        throw new Error("No APK file selected.");
    }
    if (!apkFile.name.toLowerCase().endsWith(".apk")) {
        showError("❌ Selected file is not an APK. Please choose a .apk file.");
        throw new Error("Selected file is not an APK.");
    }
    const fd = new FormData();
    fd.append("file", apkFile, apkFile.name);
    return fetchJSON(`${API_BASE}/scan-apk`, { method: "POST", body: fd });
}

async function fetchJSON(url, options) {
    const res = await fetch(url, options);
    if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try { const d = await res.json(); msg = d.detail || msg; } catch {}
        throw new Error(msg);
    }
    return res.json();
}

// ──────────────────────────────────────────────────────────────────
// Display results (VirusTotal-style)
// ──────────────────────────────────────────────────────────────────
function displayResults(data) {
    // ── Scores ──
    const score    = data.risk_score ?? 0;
    const status   = (data.status ?? data.verdict ?? "Unknown").toString().toUpperCase();
    const reasons  = data.reasons ?? [];
    const keywords = data.keywords_found ?? [];
    const mlConf   = data.ml_probability ?? data.ml_confidence ?? data.phishing_prob ?? data.confidence ?? 0;
    const hScore   = data.heuristic_score ?? 0;
    const urlRisks = data.url_risks ?? [];
    const mlFeats  = data.top_ml_features ?? [];
    const modelName= data.model_name ?? data.analysis_type ?? "ML";

    // ── Color ──
    // For safe files (score 0-5 with Safe status), use green only
    const isSafe = score <= 5 && (status === "SAFE" || status === "Safe");
    const color = isSafe ? "#00ff66" : (score >= 60 ? "#ff003c" : score >= 30 ? "#ffaa00" : "#00ff66");

    // ── Circular meter animation ──
    animateMeter(score, color);

    // ── Status label ──
    const emoji = isSafe ? "✅" : (score >= 60 ? "🔴" : score >= 30 ? "🟡" : "🟢");
    const riskStatus = document.getElementById("riskStatus");
    riskStatus.textContent = `${emoji} ${status}`;
    riskStatus.style.color = color;
    riskStatus.style.textShadow = isSafe ? "none" : `0 0 15px ${color}`;

    // ── Score breakdown bars (ONLY if not safe) ──
    const breakdown = document.getElementById("scoreBreakdown");
    if (isSafe) {
        breakdown.style.display = "none";
    } else {
        breakdown.style.display = "block";
        setBar("heuristicBar", hScore, color);
        setBar("mlBar",        mlConf,  "#00d4ff");
        document.getElementById("heuristicVal").textContent = `${Math.round(hScore)}%`;
        document.getElementById("mlVal").textContent        = `${Math.round(mlConf)}%`;
    }

    // ── Indicators tab ──
    const reasonsList = document.getElementById("reasonsList");
    if (reasons.length) {
        reasonsList.innerHTML = reasons.map(r =>
            `<li><i class="fa-solid fa-triangle-exclamation" style="color:${color}"></i> ${escHtml(r)}</li>`
        ).join("");
    } else {
        reasonsList.innerHTML = `<li><i class="fa-solid fa-check-circle" style="color:#00ff66"></i> No threats detected.</li>`;
    }

    // APK-specific
    if (data.permissions?.length) {
        reasonsList.innerHTML += data.permissions.slice(0, 5).map(p =>
            `<li><i class="fa-solid fa-lock" style="color:#ff9500"></i> Permission: ${escHtml(p)}</li>`
        ).join("");
    }
    if (data.malware_indicators?.length) {
        reasonsList.innerHTML += data.malware_indicators.map(m =>
            `<li><i class="fa-solid fa-virus" style="color:#ff003c"></i> Malware signature: ${escHtml(m)}</li>`
        ).join("");
    }

    // Audio transcription
    if (data.transcription) {
        reasonsList.innerHTML +=
            `<li><i class="fa-solid fa-microphone" style="color:#00d4ff"></i> Transcription: "${escHtml(data.transcription.substring(0, 120))}…"</li>`;
    }

    // ── Keywords tab ──
    const cloud = document.getElementById("keywordsCloud");
    if (keywords.length) {
        cloud.innerHTML = keywords.map(k =>
            `<span class="kw-chip" style="border-color:${color};color:${color}">${escHtml(k)}</span>`
        ).join("");
    } else {
        cloud.innerHTML = "<p style='color:var(--text-muted)'>No suspicious keywords found.</p>";
    }

    // ── URLs tab ──
    const urlDiv = document.getElementById("urlRisksList");
    if (urlRisks.length) {
        urlDiv.innerHTML = urlRisks.map(u => {
            const uc = u.risk_score >= 60 ? "#ff003c" : u.risk_score >= 30 ? "#ffaa00" : "#00ff66";
            return `<div class="url-risk-item">
                <div class="url-risk-header">
                    <span class="url-risk-score" style="background:${uc}">${u.risk_score}%</span>
                    <span class="url-risk-verdict" style="color:${uc}">${u.verdict}</span>
                    <span class="url-risk-domain">${escHtml(u.domain || u.url?.substring(0, 60))}</span>
                </div>
                <ul>${(u.reasons||[]).slice(0,3).map(r => `<li>${escHtml(r)}</li>`).join("")}</ul>
            </div>`;
        }).join("");
    } else {
        urlDiv.innerHTML = "<p style='color:var(--text-muted)'>No URLs detected or analyzed.</p>";
    }
    
    // ── Analysis Reasons tab (paragraph) ──
    const reasonsDiv = document.getElementById("reasonsParagraph");
    if (data.reason_paragraph) {
        reasonsDiv.innerHTML = `<p class="reason-text">${escHtml(data.reason_paragraph)}</p>
            <div class="analysis-meta" style="margin-top:16px;padding-top:16px;border-top:1px solid rgba(255,255,255,0.1)">
                <div class="meta-item"><strong>Confidence:</strong> <span style="color:${color}">${escHtml(data.confidence?.toString() ?? "Medium")}</span></div>
                <div class="meta-item"><strong>Risk Score:</strong> <span style="color:${color}">${score}%</span></div>
                <div class="meta-item"><strong>Status:</strong> <span style="color:${color}">${status}</span></div>
            </div>`;
    } else {
        reasonsDiv.innerHTML = "<p style='color:var(--text-muted)'>No analysis summary available.</p>";
    }
    
    // ── Details tab (metadata) ──
    const detailsDiv = document.getElementById("detailsSection");
    if (data.details) {
        let detailsHtml = `<div class="detail-item">
            <i class="fa-solid fa-info-circle"></i>
            <div><strong>Analysis Type:</strong><span>${escHtml(data.analysis_type || "unknown")}</span></div>
        </div>`;
        
        if (data.details.file_name) {
            detailsHtml += `<div class="detail-item">
                <i class="fa-solid fa-file"></i>
                <div><strong>File Name:</strong><span>${escHtml(data.details.file_name)}</span></div>
            </div>`;
        }
        
        if (data.details.file_size_bytes) {
            const sizeKB = Math.round(data.details.file_size_bytes / 1024);
            detailsHtml += `<div class="detail-item">
                <i class="fa-solid fa-weight"></i>
                <div><strong>File Size:</strong><span>${sizeKB} KB</span></div>
            </div>`;
        }
        
        if (data.details.file_type) {
            detailsHtml += `<div class="detail-item">
                <i class="fa-solid fa-cube"></i>
                <div><strong>File Type:</strong><span>${escHtml(data.details.file_type)}</span></div>
            </div>`;
        }
        
        if (data.details.md5) {
            detailsHtml += `<div class="detail-item">
                <i class="fa-solid fa-fingerprint"></i>
                <div><strong>MD5 Hash:</strong><span class="mono">${escHtml(data.details.md5)}</span></div>
            </div>`;
        }
        
        if (data.details.sha256) {
            detailsHtml += `<div class="detail-item">
                <i class="fa-solid fa-fingerprint"></i>
                <div><strong>SHA256 Hash:</strong><span class="mono">${escHtml(data.details.sha256)}</span></div>
            </div>`;
        }
        
        if (data.details.urls_found) {
            detailsHtml += `<div class="detail-item">
                <i class="fa-solid fa-link"></i>
                <div><strong>URLs Found:</strong><span>${data.details.urls_found}</span></div>
            </div>`;
        }
        
        if (data.details.domains && data.details.domains.length > 0) {
            detailsHtml += `<div class="detail-item">
                <i class="fa-solid fa-globe"></i>
                <div><strong>Domains:</strong><span>${data.details.domains.slice(0, 3).map(d => escHtml(d)).join(", ")}</span></div>
            </div>`;
        }
        
        if (data.details.text_length) {
            detailsHtml += `<div class="detail-item">
                <i class="fa-solid fa-align-left"></i>
                <div><strong>Text Length:</strong><span>${data.details.text_length} characters</span></div>
            </div>`;
        }
        
        detailsDiv.innerHTML = detailsHtml || "<p style='color:var(--text-muted)'>No detailed information available.</p>";
    } else {
        detailsDiv.innerHTML = "<p style='color:var(--text-muted)'>No detailed information available.</p>";
    }

    // ── ML Explainability tab (ONLY if threats detected) ──
    const mlDiv = document.getElementById("mlExplanation");
    if (isSafe || mlConf < 30) {
        mlDiv.innerHTML = "<p style='color:var(--text-muted)'>No significant ML-based threats detected. This content appears safe.</p>";
    } else {
        let mlHtml = `<div class="ml-stat">
            <span>Model:</span><strong style="color:#00d4ff">${escHtml(modelName)}</strong>
        </div>
        <div class="ml-stat">
            <span>Phishing Probability:</span>
            <strong style="color:${color}">${Math.round(mlConf)}%</strong>
        </div>`;
        if (mlFeats.length) {
            mlHtml += `<h4 style="margin-top:12px;color:var(--text-muted)">Top Influencing Words:</h4>`;
            mlHtml += mlFeats.map(([word, weight]) => {
                const w = Math.min(Math.abs(weight) * 200, 100);
                const c = weight > 0 ? "#ff003c" : "#00ff66";
                return `<div class="ml-feature">
                    <span class="ml-word">${escHtml(word)}</span>
                    <div class="ml-bar-track"><div class="ml-bar-fill" style="width:${w}%;background:${c}"></div></div>
                    <span class="ml-weight" style="color:${c}">${weight > 0 ? "+" : ""}${weight.toFixed(3)}</span>
                </div>`;
            }).join("");
        }
        mlDiv.innerHTML = mlHtml;
    }

    // ── VirusTotal summary bar (ONLY for suspicious/phishing) ──
    const vtSummary = document.getElementById("vtSummary");
    if (isSafe) {
        vtSummary.style.display = "none";
    } else {
        vtSummary.style.display = "grid";
        const safeCount  = reasons.filter(r => r.toLowerCase().includes("safe")).length;
        const suspCount  = reasons.filter(r => r.toLowerCase().includes("suspicious") || r.toLowerCase().includes("url shortener")).length;
        const phishCount = reasons.filter(r => r.toLowerCase().includes("phishing") || r.toLowerCase().includes("high risk")).length;
        document.getElementById("vtSafeCount").textContent  = safeCount;
        document.getElementById("vtSuspCount").textContent  = suspCount;
        document.getElementById("vtPhishCount").textContent = phishCount;
        document.getElementById("vtModel").textContent      = modelName;
    }

    // Reset to first tab
    document.querySelectorAll(".detail-tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".detail-panel").forEach(p => p.classList.remove("active"));
    document.querySelector('.detail-tab[data-detail="indicators"]').classList.add("active");
    document.getElementById("detail-indicators").classList.add("active");
}

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────
function animateMeter(targetScore, color) {
    const circle  = document.getElementById("progressCircle");
    const pctEl   = document.getElementById("riskPercentage");
    pctEl.style.color = color;
    let cur = 0;
    const tick = setInterval(() => {
        cur = Math.min(cur + 2, targetScore);
        circle.style.background =
            `conic-gradient(${color} ${cur * 3.6}deg, #222 ${cur * 3.6}deg)`;
        pctEl.textContent = `${cur}%`;
        if (cur >= targetScore) clearInterval(tick);
    }, 12);
}

function setBar(id, val, color) {
    const el = document.getElementById(id);
    if (el) { el.style.width = `${Math.round(val)}%`; el.style.background = color; }
}

function setLoadingState(btn) {
    btn.disabled = true;
    btn.innerHTML = `<span>⏳ ANALYZING…</span>`;
    const riskStatus = document.getElementById("riskStatus");
    riskStatus.textContent = "🔄 Analyzing…";
    riskStatus.style.color = "var(--text-main)";
    riskStatus.style.textShadow = "none";
    document.getElementById("reasonsList").innerHTML =
        "<li><i class='fa-solid fa-spinner fa-spin'></i> Scanning patterns…</li>";
    document.getElementById("scoreBreakdown").style.display = "none";
    document.getElementById("vtSummary").style.display = "none";
    document.getElementById("progressCircle").style.background =
        "conic-gradient(#555 0deg, #555 360deg)";
    document.getElementById("riskPercentage").textContent = "0%";
}

function showError(msg) {
    document.getElementById("result").classList.remove("hidden");
    document.getElementById("result").scrollIntoView({ behavior: "smooth" });
    document.getElementById("riskStatus").textContent = msg;
    document.getElementById("riskStatus").style.color = "#ff003c";
    document.getElementById("reasonsList").innerHTML =
        "<li>Please check your input and try again.</li>";
}

function escHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}
