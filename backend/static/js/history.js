/* history.js - PhishShield scan logs query and layout binding */

export function loadHistory() {
    fetch("/api/history")
        .then(res => res.json())
        .then(history => {
            const historyList = document.getElementById("historyList");
            const historyPlaceholder = document.getElementById("historyPlaceholder");
            const recentScansList = document.getElementById("recentScansList");
            const recentPlaceholder = document.getElementById("recentPlaceholder");
            
            // Clear old items
            if (historyList) historyList.innerHTML = "";
            if (recentScansList) recentScansList.innerHTML = "";
            
            if (history.length === 0) {
                if (historyPlaceholder) historyPlaceholder.classList.remove("hidden");
                if (recentPlaceholder) recentPlaceholder.classList.remove("hidden");
                return;
            }
            
            if (historyPlaceholder) historyPlaceholder.classList.add("hidden");
            if (recentPlaceholder) recentPlaceholder.classList.add("hidden");
            
            // Process recent 3 scans for home screen widget
            const recentScans = history.slice(0, 3);
            recentScans.forEach(item => {
                if (!recentScansList) return;
                const li = createHistoryLiElement(item);
                recentScansList.appendChild(li);
            });
            
            // Process complete history scans
            history.forEach(item => {
                if (!historyList) return;
                const li = createHistoryLiElement(item);
                historyList.appendChild(li);
            });
        })
        .catch(err => {
            console.error("Failed to load scan history logs:", err);
        });
}

function createHistoryLiElement(item) {
    const li = document.createElement("li");
    li.className = "history-item";
    
    let badgeClass = "badge-safe";
    let badgeText = item.verdict;
    if (item.verdict === "Low Suspicious") badgeClass = "badge-suspicious-low";
    if (item.verdict === "High Suspicious") badgeClass = "badge-suspicious-high";
    if (item.verdict === "Suspicious") badgeClass = "badge-suspicious";
    if (item.verdict === "High Risk") badgeClass = "badge-risk";
    if (item.is_legacy) {
        badgeClass = "badge-suspicious";
        badgeText = "Legacy";
    }
    
    const timeStr = new Date(item.scanned_at).toLocaleDateString(undefined, {month:'short', day:'numeric'}) + ' ' + new Date(item.scanned_at).toLocaleTimeString(undefined, {hour:'2-digit', minute:'2-digit'});

    li.innerHTML = `
        <div class="history-meta">
            <h4>${item.url}</h4>
            <span>Score: ${item.score} &bull; ${timeStr}</span>
        </div>
        <span class="history-badge ${badgeClass}">${badgeText}</span>
    `;
    
    // Click history item to load report details
    li.addEventListener("click", () => {
        loadScanDetails(item.id);
    });

    return li;
}

function loadScanDetails(scanId) {
    fetch(`/api/history/${scanId}`)
        .then(res => {
            if (!res.ok) throw new Error("Could not retrieve historical details");
            return res.json();
        })
        .then(data => {
            if (window.App && typeof window.App.renderScanResults === "function") {
                window.App.renderScanResults(data);
            }
        })
        .catch(err => {
            alert(`Error loading scan: ${err.message}`);
        });
}
