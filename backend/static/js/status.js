/* status.js - API & Database Engine Status checks */

export function loadSystemStatus() {
    fetch("/api/status")
        .then(res => res.json())
        .then(status => {
            const statusGSB = document.getElementById("statusGSB");
            const statusPhishTank = document.getElementById("statusPhishTank");
            const statusDB = document.getElementById("statusDB");
            
            if (statusGSB) {
                statusGSB.innerText = status.google_safe_browsing;
                statusGSB.className = `status-indicator-badge ${status.google_safe_browsing.toLowerCase()}`;
            }
            if (statusPhishTank) {
                statusPhishTank.innerText = status.phishtank;
                statusPhishTank.className = `status-indicator-badge ${status.phishtank.toLowerCase()}`;
            }
            if (statusDB) {
                statusDB.innerText = status.database;
                statusDB.className = `status-indicator-badge ${status.database.toLowerCase()}`;
            }
            
            // Show database state label dynamically in header if it exists
            const dbTypeLabel = document.getElementById("dbTypeLabel");
            if (dbTypeLabel) {
                dbTypeLabel.innerText = `${status.database} Active`;
            }
            
            // Footer status badge
            const apiStatusBadge = document.getElementById("apiStatusBadge");
            if (apiStatusBadge) {
                apiStatusBadge.className = "status-badge-green";
                apiStatusBadge.innerHTML = `<span class="bullet"></span>Services Online`;
            }
        })
        .catch(err => {
            console.error("Failed to load engine connectivity status:", err);
            const dbTypeLabel = document.getElementById("dbTypeLabel");
            if (dbTypeLabel) {
                dbTypeLabel.innerText = "Services Error";
            }
            const apiStatusBadge = document.getElementById("apiStatusBadge");
            if (apiStatusBadge) {
                apiStatusBadge.className = "status-badge-red";
                apiStatusBadge.innerHTML = `<span class="bullet"></span>Services Offline`;
            }
        });
}
