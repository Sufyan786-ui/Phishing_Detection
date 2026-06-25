/* scanner.js - PhishShield Scanner forms and loader animations */

import { switchView } from "./navigation.js";
import { renderScanResults } from "./analysis.js";
import { loadHistory } from "./history.js";

// State
export let isScanning = false;

export function initScanner() {
    const scanForm = document.getElementById("scanForm");
    const urlInput = document.getElementById("urlInput");
    const quickTests = document.querySelectorAll(".btn-test");

    if (scanForm) {
        scanForm.addEventListener("submit", (e) => {
            e.preventDefault();
            triggerScan();
        });
    }

    if (quickTests) {
        quickTests.forEach(btn => {
            btn.addEventListener("click", () => {
                if (isScanning) return;
                if (urlInput) {
                    urlInput.value = btn.getAttribute("data-url");
                    triggerScan();
                }
            });
        });
    }
}

export function triggerScan() {
    if (isScanning) return;
    const urlInput = document.getElementById("urlInput");
    const scannerLoader = document.getElementById("scannerLoader");
    if (!urlInput) return;

    const targetUrl = urlInput.value.trim();
    if (!targetUrl) return;

    isScanning = true;
    switchView("scanner");
    if (scannerLoader) scannerLoader.classList.remove("hidden");
    
    // Reset steps loader visuals
    resetLoaderSteps();

    // 1. Initiate API request
    fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl })
    }).then(res => {
        if (!res.ok) {
            return res.json().then(err => { throw new Error(err.detail || "Scan request failed"); });
        }
        return res.json();
    })
    .then(data => {
        // 2. Control visual step indicators dynamically based on real backend skipping
        return animateLoaderSteps(data);
    })
    .then(data => {
        // Hide loader and display data
        if (scannerLoader) scannerLoader.classList.add("hidden");
        renderScanResults(data);
        loadHistory(); // Reload history logs
        isScanning = false;
    })
    .catch(err => {
        if (scannerLoader) scannerLoader.classList.add("hidden");
        console.error("URL scan failed:", err);
        alert(`Scan failed: ${err.message}\n\nPlease verify that the backend server is running, then try again.`);
        isScanning = false;
    });
}

function resetLoaderSteps() {
    const stepLexical = document.getElementById("step-lexical");
    const stepThreat = document.getElementById("step-threat");
    const stepContent = document.getElementById("step-content");
    const stepSimilarity = document.getElementById("step-similarity");

    [stepLexical, stepThreat, stepContent, stepSimilarity].forEach(step => {
        if (!step) return;
        step.className = "step-item";
        const icon = step.querySelector(".step-icon");
        if (icon) icon.setAttribute("data-lucide", "clock");
    });
    
    // Restore original span texts
    if (stepLexical) stepLexical.querySelector("span").innerText = "Analyzing URL lexical patterns...";
    if (stepThreat) stepThreat.querySelector("span").innerText = "Querying GSB & PhishTank feeds...";
    if (stepContent) stepContent.querySelector("span").innerText = "Inspecting HTML document structure...";
    if (stepSimilarity) stepSimilarity.querySelector("span").innerText = "Performing brand similarity comparison...";
    
    if (window.lucide) window.lucide.createIcons();
}

function animateLoaderSteps(data) {
    const stepDelay = 400; // ms
    const details = data.details || {};
    const threatIntel = details.threat_intel || {};
    const isFlagged = threatIntel.is_flagged;

    const stepLexical = document.getElementById("step-lexical");
    const stepThreat = document.getElementById("step-threat");
    const stepContent = document.getElementById("step-content");
    const stepSimilarity = document.getElementById("step-similarity");
    
    return new Promise(resolve => {
        // Step 1 active
        setStepState(stepLexical, "active", "loader");
        
        setTimeout(() => {
            setStepState(stepLexical, "success", "check-circle");
            if (stepLexical) stepLexical.querySelector("span").innerText = "URL lexical patterns analyzed.";
            
            // Step 2 active
            setStepState(stepThreat, "active", "loader");
            
            setTimeout(() => {
                if (isFlagged) {
                    setStepState(stepThreat, "critical", "shield-alert");
                    if (stepThreat) stepThreat.querySelector("span").innerText = "Threat Intel matched! Blacklist confirmed.";
                    
                    // Step 3 & 4 skipped
                    setStepState(stepContent, "skipped", "ban");
                    if (stepContent) stepContent.querySelector("span").innerText = "Secondary checks skipped (Threat Intel matched)";
                    
                    setStepState(stepSimilarity, "skipped", "ban");
                    if (stepSimilarity) stepSimilarity.querySelector("span").innerText = "Secondary checks skipped (Threat Intel matched)";
                    
                    setTimeout(() => {
                        resolve(data);
                    }, stepDelay);
                } else {
                    setStepState(stepThreat, "success", "check-circle");
                    if (stepThreat) stepThreat.querySelector("span").innerText = "GSB & PhishTank checked: Clean";
                    
                    // Step 3 active
                    setStepState(stepContent, "active", "loader");
                    
                    setTimeout(() => {
                        setStepState(stepContent, "success", "check-circle");
                        if (stepContent) stepContent.querySelector("span").innerText = "HTML document structure inspected.";
                        
                        // Step 4 active
                        setStepState(stepSimilarity, "active", "loader");
                        
                        setTimeout(() => {
                            setStepState(stepSimilarity, "success", "check-circle");
                            if (stepSimilarity) stepSimilarity.querySelector("span").innerText = "Brand similarity comparison completed.";
                            
                            setTimeout(() => {
                                resolve(data);
                            }, stepDelay);
                        }, stepDelay);
                    }, stepDelay);
                }
            }, stepDelay);
        }, stepDelay);
    });
}

function setStepState(element, state, iconName) {
    if (!element) return;
    element.className = `step-item ${state}`;
    const icon = element.querySelector(".step-icon");
    if (icon) icon.setAttribute("data-lucide", iconName);
    if (window.lucide) window.lucide.createIcons();
}
