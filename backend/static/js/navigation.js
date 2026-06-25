/* navigation.js - SPA Navigation & View Routing */

export function initNavigation() {
    const scannerNavBtn = document.getElementById("scannerNavBtn");
    const analysisNavBtn = document.getElementById("analysisNavBtn");
    const historyNavBtn = document.getElementById("historyNavBtn");
    const footerNewScanLink = document.getElementById("footerNewScanLink");
    const urlInput = document.getElementById("urlInput");

    if (scannerNavBtn) {
        scannerNavBtn.addEventListener("click", () => switchView("scanner"));
    }
    
    if (analysisNavBtn) {
        analysisNavBtn.addEventListener("click", () => {
            if (window.App.hasAnalysisResult) switchView("analysis");
        });
    }

    if (historyNavBtn) {
        historyNavBtn.addEventListener("click", () => switchView("history"));
    }

    if (footerNewScanLink) {
        footerNewScanLink.addEventListener("click", (event) => {
            event.preventDefault();
            switchView("scanner");
            if (urlInput) urlInput.focus();
        });
    }
}

export function switchView(viewName) {
    const scannerView = document.getElementById("scannerView");
    const analysisView = document.getElementById("analysisView");
    const historyView = document.getElementById("historyView");
    
    const scannerNavBtn = document.getElementById("scannerNavBtn");
    const analysisNavBtn = document.getElementById("analysisNavBtn");
    const historyNavBtn = document.getElementById("historyNavBtn");

    if (scannerView) scannerView.classList.toggle("hidden", viewName !== "scanner");
    if (analysisView) analysisView.classList.toggle("hidden", viewName !== "analysis");
    if (historyView) historyView.classList.toggle("hidden", viewName !== "history");
    
    if (scannerNavBtn) scannerNavBtn.classList.toggle("active", viewName === "scanner");
    if (analysisNavBtn) analysisNavBtn.classList.toggle("active", viewName === "analysis");
    if (historyNavBtn) historyNavBtn.classList.toggle("active", viewName === "history");
    
    if (viewName === "analysis") {
        if (analysisView) analysisView.scrollIntoView({ behavior: "smooth" });
    } else if (viewName === "scanner") {
        if (scannerView) scannerView.scrollIntoView({ behavior: "smooth" });
    } else if (viewName === "history") {
        if (historyView) historyView.scrollIntoView({ behavior: "smooth" });
        if (window.App && typeof window.App.loadHistory === "function") {
            window.App.loadHistory();
        }
    }
}
