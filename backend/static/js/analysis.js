/* analysis.css - PhishShield Report Analytics Renderer */

import { switchView } from "./navigation.js";

export function renderScanResults(data) {
    window.App.hasAnalysisResult = true;
    
    const analysisNavBtn = document.getElementById("analysisNavBtn");
    if (analysisNavBtn) analysisNavBtn.disabled = false;
    
    switchView("analysis");

    // Elements
    const resultVerdict = document.getElementById("resultVerdict");
    const resultUrl = document.getElementById("resultUrl");
    const scanTimestamp = document.getElementById("scanTimestamp");
    const gaugeIndicator = document.getElementById("gaugeIndicator");
    const recommendationBlock = document.getElementById("recommendationBlock");
    const recIconElement = document.getElementById("recIconElement");
    const recTitle = document.getElementById("recTitle");
    const recBody = document.getElementById("recBody");

    // Update score & verdict
    animateScoreCount(data.score);
    if (resultVerdict) resultVerdict.innerText = data.verdict.toUpperCase();
    if (resultUrl) resultUrl.innerText = data.url;
    
    // Format timestamp
    const dateStr = new Date(data.scanned_at).toLocaleString();
    if (scanTimestamp) scanTimestamp.innerText = `Scanned at: ${dateStr}`;

    // Reset gauge color class and set path values
    const offset = 220 - (220 * data.score / 100);
    if (gaugeIndicator) {
        gaugeIndicator.style.strokeDashoffset = offset;
        gaugeIndicator.className.baseVal = "gauge-fill";
    }
    
    if (resultVerdict) resultVerdict.className = "gauge-verdict";
    
    // Render Confidence Score
    if (resultVerdict && data.confidence_score !== undefined) {
        let confidenceEl = document.getElementById("resultConfidence");
        if (!confidenceEl) {
            confidenceEl = document.createElement("span");
            confidenceEl.id = "resultConfidence";
            confidenceEl.style.fontSize = "0.7rem";
            confidenceEl.style.marginTop = "3px";
            confidenceEl.style.color = "var(--text-tertiary)";
            confidenceEl.style.fontWeight = "600";
            confidenceEl.style.display = "block";
            resultVerdict.parentNode.appendChild(confidenceEl);
        }
        confidenceEl.innerText = `Confidence: ${data.confidence_score}%`;
    } else {
        const confidenceEl = document.getElementById("resultConfidence");
        if (confidenceEl) confidenceEl.remove();
    }
    
    if (data.verdict === "Safe") {
        if (gaugeIndicator) gaugeIndicator.classList.add("fill-safe");
        if (resultVerdict) resultVerdict.classList.add("text-safe");
        
        if (recommendationBlock) recommendationBlock.className = "recommendation-box box-safe";
        if (recIconElement) recIconElement.setAttribute("data-lucide", "shield-check");
        if (recTitle) recTitle.innerText = "Safety Recommendation: SAFE";
    } else if (data.verdict === "Low Suspicious") {
        if (gaugeIndicator) gaugeIndicator.classList.add("fill-suspicious-low");
        if (resultVerdict) resultVerdict.classList.add("text-suspicious-low");
        
        if (recommendationBlock) recommendationBlock.className = "recommendation-box box-suspicious-low";
        if (recIconElement) recIconElement.setAttribute("data-lucide", "shield-alert");
        if (recTitle) recTitle.innerText = "Safety Recommendation: LOW SUSPICIOUS";
    } else if (data.verdict === "High Suspicious") {
        if (gaugeIndicator) gaugeIndicator.classList.add("fill-suspicious-high");
        if (resultVerdict) resultVerdict.classList.add("text-suspicious-high");
        
        if (recommendationBlock) recommendationBlock.className = "recommendation-box box-suspicious-high";
        if (recIconElement) recIconElement.setAttribute("data-lucide", "shield-alert");
        if (recTitle) recTitle.innerText = "Safety Recommendation: HIGH SUSPICIOUS";
    } else {
        if (gaugeIndicator) gaugeIndicator.classList.add("fill-risk");
        if (resultVerdict) resultVerdict.classList.add("text-risk");
        
        if (recommendationBlock) recommendationBlock.className = "recommendation-box box-risk";
        if (recIconElement) recIconElement.setAttribute("data-lucide", "shield-alert");
        if (recTitle) recTitle.innerText = "Safety Recommendation: HIGH RISK";
    }

    // Render Dynamic Detection Mode Badge
    const detectionModeBadge = document.getElementById("detectionModeBadge");
    if (detectionModeBadge) {
        const isFlagged = data.details && data.details.threat_intel && data.details.threat_intel.is_flagged;
        if (isFlagged) {
            detectionModeBadge.innerText = "Mode: Threat Intelligence Confirmation";
            detectionModeBadge.className = "mode-badge threat-intel";
        } else {
            detectionModeBadge.innerText = "Mode: Zero-Day Analysis";
            detectionModeBadge.className = "mode-badge zero-day";
        }
    }

    // Render Why this verdict? explanation
    const verdictSummaryText = document.getElementById("verdictSummaryText");
    if (verdictSummaryText) {
        verdictSummaryText.innerText = data.verdict_summary || "No automated explanation available.";
    }

    // Render Recommendations Text
    if (recBody) recBody.innerHTML = formatMarkdownLike(data.recommendations);
    renderRiskBreakdown(data);
    renderComponentBars(data);

    // Render Checklists
    renderUrlFeatures(data.details.url_features);
    renderThreatIntel(data.details.threat_intel);
    renderContentAnalysis(data.details.content_analysis);
    renderSimilarity(data.details.similarity);

    if (window.lucide) window.lucide.createIcons();
}

function renderRiskBreakdown(data) {
    const riskBreakdownList = document.getElementById("riskBreakdownList");
    const analysisModeLabel = document.getElementById("analysisModeLabel");
    if (!riskBreakdownList) return;
    
    riskBreakdownList.innerHTML = "";
    const details = data.details || {};
    const threat = details.threat_intel || {};
    const urlFeat = details.url_features || {};
    const content = details.content_analysis || {};
    const sim = details.similarity || {};

    if (threat.is_flagged) {
        if (analysisModeLabel) analysisModeLabel.innerText = "Threat intelligence confirmation mode";
        addRiskBreakdownItem(riskBreakdownList, "critical", "Threat Intelligence", 100, "URL is listed by a blacklist provider, so the system directly classified it as High Risk.");
        addRiskBreakdownItem(riskBreakdownList, "warning", "Secondary Analysis", 0, "URL, content, and brand checks were skipped because a confirmed blacklist match is already decisive.");
        return;
    }

    if (analysisModeLabel) analysisModeLabel.innerText = "Zero-day analysis mode: URL was not found in blacklist feeds";

    const items = [
        {
            label: "URL ML / Lexical Pattern",
            score: Number(urlFeat.feature_score || 0),
            detail: urlFeat.status === "legacy"
                ? "Legacy URL score is not comparable with the current model. Run this URL again for a current score."
                : `Calibrated URL score using ML and lexical indicators. Raw ML: ${formatScore(urlFeat.raw_ml_score)}, heuristic: ${formatScore(urlFeat.heuristic_score)}.`
        },
        {
            label: "HTML Content Behavior",
            score: Number(content.feature_score || 0),
            detail: "Page behavior such as forms, hidden inputs, external form actions, iframe hiding, scripts, and SSL issues."
        },
        {
            label: "Brand Impersonation",
            score: Number(sim.feature_score || 0),
            detail: sim.impersonation_detected ? sim.reason : "No strong brand-domain mismatch or favicon impersonation was found."
        }
    ].sort((a, b) => b.score - a.score);

    items.forEach(item => {
        addRiskBreakdownItem(riskBreakdownList, scoreLevel(item.score), item.label, item.score, item.detail);
    });
}

function scoreLevel(score) {
    if (score >= 70) return "critical";
    if (score >= 50) return "warning-high";
    if (score >= 30) return "warning-low";
    return "ok";
}

function formatScore(score) {
    return score === null || score === undefined ? "not used" : `${score}/100`;
}

function addRiskBreakdownItem(parent, iconType, label, score, detail) {
    const item = document.createElement("div");
    item.className = `risk-breakdown-item ${iconType}`;
    
    const scoreHtml = (score === 0 && iconType === "ok") 
        ? `<span class="risk-breakdown-score safe-badge">SAFE</span>`
        : (score === 0 && label === "Secondary Analysis")
            ? `<span class="risk-breakdown-score">Skipped</span>`
            : `<span class="risk-breakdown-score">${score}/100</span>`;
        
    item.innerHTML = `
        <div class="risk-breakdown-top">
            <span class="risk-breakdown-label">${label}</span>
            ${scoreHtml}
        </div>
        <div class="risk-meter" aria-hidden="true">
            <span style="width: ${Math.max(0, Math.min(10, Math.round(score / 10)) * 10)}%"></span>
        </div>
        <p>${detail}</p>
    `;
    parent.appendChild(item);
}

function renderComponentBars(data) {
    const contributionBars = document.getElementById("contributionBars");
    if (!contributionBars) return;
    
    contributionBars.innerHTML = "";
    const details = data.details || {};
    const threat = details.threat_intel || {};
    const urlFeat = details.url_features || {};
    const content = details.content_analysis || {};
    const sim = details.similarity || {};
    
    const list = [
        {
            name: "URL ML / Lexical",
            score: ["skipped", "legacy"].includes(urlFeat.status) ? null : (urlFeat.feature_score || 0),
            status: urlFeat.status
        },
        {
            name: "HTML Content",
            score: content.status === "skipped" ? null : (content.feature_score || 0),
            status: content.status
        },
        {
            name: "Brand Impersonation",
            score: sim.status === "skipped" ? null : (sim.feature_score || 0),
            status: sim.status
        },
        {
            name: "Threat Intel",
            score: threat.is_flagged ? 100 : null,
            isThreatIntel: true,
            isFlagged: threat.is_flagged
        }
    ];
    
    list.forEach(item => {
        const row = document.createElement("div");
        row.className = "contrib-row";
        
        let valueText = "";
        let asciiBar = "";
        let percentage = 0;
        
        if (item.isThreatIntel) {
            if (item.isFlagged) {
                valueText = "Matched";
                percentage = 100;
                asciiBar = getBlockBar(100);
            } else {
                valueText = "Not listed";
                percentage = 0;
                asciiBar = getBlockBar(0);
            }
        } else {
            if (item.status === "skipped" || item.status === "legacy") {
                valueText = item.status === "legacy" ? "Legacy" : "Skipped";
                percentage = 0;
                asciiBar = getBlockBar(0);
            } else {
                valueText = `${item.score}`;
                percentage = item.score;
                asciiBar = getBlockBar(item.score);
            }
        }
        
        let displayValue = valueText;
        let valueClass = "contrib-value";
        
        if (["Not listed", "Skipped", "Legacy"].includes(valueText)) {
            valueClass = "contrib-value not-listed";
        } else if (valueText === "Matched") {
            valueClass = "contrib-value matched";
        } else if (item.score === 0) {
            valueClass = "contrib-value safe-badge";
            displayValue = "SAFE";
        }
        
        row.innerHTML = `
            <span class="contrib-label">${item.name}</span>
            <div class="contrib-bar-wrapper">
                <span class="contrib-ascii">${asciiBar}</span>
                <div class="contrib-percentage-bar">
                    <span style="width: ${percentage}%"></span>
                </div>
            </div>
            <span class="${valueClass}">${displayValue}</span>
        `;
        
        contributionBars.appendChild(row);
    });
}

function getBlockBar(score) {
    if (score === null || score === undefined || isNaN(score)) return "░░░░░░░░░░";
    const filled = Math.max(0, Math.min(10, Math.round(score / 10)));
    return "█".repeat(filled) + "░".repeat(10 - filled);
}

function animateScoreCount(target) {
    const resultScore = document.getElementById("resultScore");
    if (!resultScore) return;
    
    let current = 0;
    const duration = 800; // ms
    const stepTime = 15;
    const steps = duration / stepTime;
    const increment = target / steps;

    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            resultScore.innerText = target;
            clearInterval(timer);
        } else {
            resultScore.innerText = Math.round(current);
        }
    }, stepTime);
}

function formatMarkdownLike(text) {
    if (!text) return "";
    let html = text;
    html = html.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    html = html.replace(/^### (.*$)/gim, "<h5>$1</h5>");
    html = html.replace(/^## (.*$)/gim, "<h4>$1</h4>");
    html = html.replace(/^# (.*$)/gim, "<h3>$1</h3>");
    html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/^\u2705 (.*$)/gim, "<div>✅ $1</div>");
    html = html.replace(/^\u26A0\uFE0F (.*$)/gim, "<div>⚠️ $1</div>");
    html = html.replace(/^\u2022 (.*$)/gim, "<li>$1</li>");
    html = html.split("\n\n").map(para => `<p>${para.replace(/\n/g, "<br>")}</p>`).join("");
    return html;
}

function renderUrlFeatures(feat) {
    const urlFeatureList = document.getElementById("urlFeatureList");
    if (!urlFeatureList) return;
    
    urlFeatureList.innerHTML = "";
    if (feat && feat.status === "skipped") {
        addFeatureItem(urlFeatureList, "warning", "URL Feature Analysis", feat.message || "Skipped after threat intelligence confirmation");
        return;
    }
    if (feat && feat.status === "legacy") {
        addFeatureItem(urlFeatureList, "warning", "Legacy URL Score", feat.message || "Run a new scan to calculate the current URL score.");
        return;
    }
    if (!feat || feat.error) {
        urlFeatureList.innerHTML = `<div class="feature-item"><i data-lucide="x-circle" class="feature-check-icon critical"></i><span>Analysis failed.</span></div>`;
        return;
    }

    addFeatureItem(urlFeatureList, feat.is_https ? "ok" : "warning", "HTTPS Secure", feat.is_https ? "HTTPS Connection Verified" : "Insecure HTTP Protocol");
    addFeatureItem(urlFeatureList, feat.is_ip_address ? "critical" : "ok", "IP Host Check", feat.is_ip_address ? "Uses raw IP hosting instead of domain" : "Domain name resolved properly");
    
    const subColor = feat.subdomain_count > 2 ? "critical" : (feat.subdomain_count > 1 ? "warning" : "ok");
    addFeatureItem(urlFeatureList, subColor, "Subdomains Count", `${feat.subdomain_count} subdomain(s) detected`);
    
    const hasSpecials = feat.char_counts.count_dot > 4 || feat.char_counts.count_hyphen > 2 || feat.char_counts.count_at > 0;
    addFeatureItem(urlFeatureList, hasSpecials ? "warning" : "ok", "Lexical Symbols", `Hyphens: ${feat.char_counts.count_hyphen}, Dots: ${feat.char_counts.count_dot}, @ Symbols: ${feat.char_counts.count_at}`);
    
    const keyColor = feat.found_keywords.length > 0 ? "critical" : "ok";
    const keyVal = feat.found_keywords.length > 0 ? `Flagged terms: ${feat.found_keywords.join(", ")}` : "No typical phishing keywords found";
    addFeatureItem(urlFeatureList, keyColor, "Phishing Keywords", keyVal);

    let ageLabel = "WHOIS age unavailable";
    let ageColor = "warning";
    if (feat.domain_age_days !== -1) {
        ageLabel = `Domain Age: ${feat.domain_age_days} days`;
        ageColor = feat.domain_age_days < 30 ? "critical" : "ok";
    }
    addFeatureItem(urlFeatureList, ageColor, "Domain Age (WHOIS)", ageLabel);

    if (feat.ml_used) {
        const mlWeight = Math.round((feat.ml_weight ?? 0.8) * 100);
        const heuristicWeight = Math.round((feat.heuristic_weight ?? 0.2) * 100);
        addFeatureItem(
            urlFeatureList,
            "ok",
            "Hybrid URL Score",
            `ML (${mlWeight}%): ${formatScore(feat.raw_ml_score)}, heuristic (${heuristicWeight}%): ${formatScore(feat.heuristic_score)}, final: ${formatScore(feat.feature_score)}`
        );
    } else {
        addFeatureItem(urlFeatureList, "warning", "URL Score Mode", `Heuristic fallback used: ${formatScore(feat.heuristic_score)}`);
    }
}

function renderThreatIntel(threat) {
    const threatIntelList = document.getElementById("threatIntelList");
    if (!threatIntelList) return;
    
    threatIntelList.innerHTML = "";
    if (!threat) return;

    const gsb = threat.google_safe_browsing;
    const pt = threat.phishtank;

    if (gsb) {
        const gsbColor = gsb.is_malicious ? "critical" : "ok";
        const gsbVal = gsb.is_malicious ? `Listed: ${gsb.threat_type}` : gsb.details;
        addFeatureItem(threatIntelList, gsbColor, gsb.provider, gsbVal);
    }

    if (pt) {
        const ptColor = pt.is_malicious ? "critical" : "ok";
        addFeatureItem(threatIntelList, ptColor, pt.provider, pt.details);
    }
}

function renderContentAnalysis(content) {
    const contentAnalysisList = document.getElementById("contentAnalysisList");
    if (!contentAnalysisList) return;
    
    contentAnalysisList.innerHTML = "";
    if (content && content.status === "skipped") {
        addFeatureItem(contentAnalysisList, "warning", "Content Analysis", content.message || "Skipped after threat intelligence confirmation");
        return;
    }
    if (!content || content.status === "failed") {
        const errText = content ? content.error : "HTML analyzer not executed";
        addFeatureItem(contentAnalysisList, "warning", "Content Scraper", errText);
        return;
    }

    const formColor = content.external_forms.length > 0 ? "critical" : "ok";
    const formVal = content.external_forms.length > 0 ? `Submits to external domain: ${content.external_forms[0]}` : `Forms verify safe (${content.forms_count} found)`;
    addFeatureItem(contentAnalysisList, formColor, "Credential Harvesting Forms", formVal);

    const hiddenColor = content.hidden_inputs_count > 5 ? "warning" : "ok";
    addFeatureItem(contentAnalysisList, hiddenColor, "Hidden Inputs", `${content.hidden_inputs_count} fields hidden from viewport`);

    const frameColor = content.hidden_iframes_count > 0 ? "critical" : "ok";
    addFeatureItem(contentAnalysisList, frameColor, "Hidden Frame Redirects", `${content.hidden_iframes_count} hidden iframe(s) detected`);

    const scriptColor = content.obfuscation_signals ? "critical" : (content.suspicious_scripts_count > 0 ? "warning-high" : "ok");
    const scriptVal = content.obfuscation_signals ? "Obfuscation keywords ('eval', 'unescape') in JS" : `${content.suspicious_scripts_count} suspicious external script source(s)`;
    addFeatureItem(contentAnalysisList, scriptColor, "Obfuscated Scripts", scriptVal);

    if (content.redirect_count !== undefined) {
        const redirectColor = content.redirect_count > 2 ? "critical" : (content.redirect_count > 0 ? "warning-low" : "ok");
        const redirectVal = content.redirect_count > 0
            ? `${content.redirect_count} redirect(s) followed: ${content.redirect_urls.map(u => u.split('/')[2] || u).join(' -> ')}`
            : "No HTTP redirects detected (direct landing)";
        addFeatureItem(contentAnalysisList, redirectColor, "Redirect Chain", redirectVal);
    }
}

function renderSimilarity(sim) {
    const similarityAnalysisList = document.getElementById("similarityAnalysisList");
    if (!similarityAnalysisList) return;
    
    similarityAnalysisList.innerHTML = "";
    if (!sim) return;
    if (sim.status === "skipped") {
        addFeatureItem(similarityAnalysisList, "warning-low", "Brand Similarity Analysis", sim.reason || "Skipped after threat intelligence confirmation");
        return;
    }

    const simColor = sim.impersonation_detected ? "critical" : "ok";
    addFeatureItem(similarityAnalysisList, simColor, "Brand Identity Match", sim.reason);
    
    if (sim.favicon_hash) {
        addFeatureItem(similarityAnalysisList, "ok", "Favicon Hash (aHash)", `Perceptual Hash: ${sim.favicon_hash}`);
    } else {
        addFeatureItem(similarityAnalysisList, "warning-low", "Favicon Analysis", "No favicon extracted from source code");
    }

    if (sim.screenshot_phash_match !== undefined) {
        const phashColor = sim.screenshot_phash_match ? "critical" : "ok";
        const phashVal = sim.screenshot_phash_match 
            ? `Perceptual Screen Layout Hash Match (pHash distance: ${sim.screenshot_phash_distance})`
            : "No screen pHash layout spoofing detected";
        addFeatureItem(similarityAnalysisList, phashColor, "Screen Perceptual pHash Check", phashVal);
    }
}

function addFeatureItem(parent, iconType, label, value) {
    const item = document.createElement("div");
    item.className = "feature-item";
    
    let iconName = "check-circle";
    if (iconType === "warning" || iconType === "warning-low" || iconType === "warning-high") iconName = "alert-triangle";
    if (iconType === "critical") iconName = "alert-circle";
    
    item.innerHTML = `
        <i data-lucide="${iconName}" class="feature-check-icon ${iconType}"></i>
        <div class="feature-info">
            <span class="feature-label">${label}</span>
            <span class="feature-val">${value}</span>
        </div>
    `;
    parent.appendChild(item);
}
