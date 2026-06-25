/* app.js - PhishShield Application Orchestrator */

import { initNavigation, switchView } from "./navigation.js";
import { loadSystemStatus } from "./status.js";
import { loadHistory } from "./history.js?v=20260625-3";
import { initScanner } from "./scanner.js?v=20260624-5";
import { renderScanResults } from "./analysis.js?v=20260625-3";

document.addEventListener("DOMContentLoaded", () => {
    // Initialize Lucide Icons
    if (window.lucide) window.lucide.createIcons();

    // Action Buttons bindings
    const newScanBtn = document.getElementById("newScanBtn");
    const printReportBtn = document.getElementById("printReportBtn");
    const closeReportBtn = document.getElementById("closeReportBtn");
    const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");
    const urlInput = document.getElementById("urlInput");

    if (newScanBtn) {
        newScanBtn.addEventListener("click", () => {
            switchView("scanner");
            if (urlInput) urlInput.focus();
        });
    }

    if (closeReportBtn) {
        closeReportBtn.addEventListener("click", () => {
            switchView("scanner");
        });
    }

    if (printReportBtn) {
        printReportBtn.addEventListener("click", () => {
            window.print();
        });
    }

    if (refreshHistoryBtn) {
        refreshHistoryBtn.addEventListener("click", loadHistory);
    }

    // Global application namespace
    window.App = {
        hasAnalysisResult: false,
        loadHistory: loadHistory,
        renderScanResults: renderScanResults
    };

    // Initialize modules
    initNavigation();
    initScanner();
    loadSystemStatus();
    loadHistory();
});
