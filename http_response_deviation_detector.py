import re
from bs4 import BeautifulSoup
from html import unescape
from detection_phase.feature_extractor import extract_js_features_from_response
import requests
from detection_phase.sanitizer_and_alert import sanitizehtmlresponse
from attack_discovery import analyze_http_response
# Encoded variants of '<'
ENCODED_VARIANTS = {
    r"\\x3C", r"\\<", r"\\u003c", r"%3C",
    r"&#x3c;", r"&#X3c;", r"&#x03c;", r"&#060;", r"&#0060;",
    "&lt;", "&LT;", "+ADw-"
}

# Rules table (simplified from Table 6, 7)
RULES = {
    'tag_text': {
        'expected': (1, 0),
        'attacks': [
            {'pattern': r"<script>alert\(\"XSS\"\)</script>", 'result': (2, 0)},
        ]
    },
    'attribute_value': {
        'expected': (1, 1),
        'attacks': [
            {'pattern': r"id1\" onfocus=\"foo\(\)\"", 'result': (1, 2)},
        ]
    }
}

def detect_encoded_injection(js_code: str) -> bool:
    """
    Detects if JavaScript code contains obfuscated variants of "<"
    """
    for variant in ENCODED_VARIANTS:
        if re.search(re.escape(variant), js_code, re.IGNORECASE):
            return True
    return False

def detect_xss_deviation(js_code: str, context_type: str) -> tuple:
    expected = RULES.get(context_type, {}).get('expected')
    for attack in RULES.get(context_type, {}).get('attacks', []):
        if re.search(attack['pattern'], js_code):
            return attack['result']
    return expected

def sanitize_html_response(html_content: str) -> tuple[str, bool]:
    """
    Automatically sanitizes potentially malicious HTML/JS from the HTTP response.
    Returns the sanitized HTML and a boolean indicating if an alert was raised.
    """
    soup = BeautifulSoup(html_content, 'html.parser')

    alert_triggered = False

    # 1. Remove or escape <script> tags
    for script_tag in soup.find_all('script'):
        script_tag.decompose()
        alert_triggered = True

    # 2. Remove dangerous event handlers (e.g., onclick, onmouseover)
    for tag in soup.find_all():
        for attr, val in list(tag.attrs.items()):
            if attr.lower().startswith("on"):
                del tag[attr]
                alert_triggered = True

    # 3. Neutralize javascript: URLs
    for tag in soup.find_all(href=True):
        if tag['href'].strip().lower().startswith("javascript:"):
            tag['href'] = "#"
            alert_triggered = True

    # 4. Sanitize dangerous inline JS functions
    dangerous_js_patterns = [
        r'eval\s*\(', r'document\.write\s*\(', r'setTimeout\s*\(', r'setInterval\s*\(',
        r'innerHTML\s*=', r'location\.href\s*='
    ]

    html_str = str(soup)
    for pattern in dangerous_js_patterns:
        new_html_str = re.sub(pattern, '/* sanitized */', html_str, flags=re.IGNORECASE)
        if new_html_str != html_str:
            alert_triggered = True
            html_str = new_html_str

    return html_str, alert_triggered

    return results
def analyze_url_response(url):
    response = requests.get(url)
    html_content = response.text  # This is a string!
    soup = BeautifulSoup(html_content, 'html.parser')

    # Example: Find all script tags
    scripts = soup.find_all('script')
    # ... perform your XSS detection logic here ...

    # Return a dictionary as expected by your Flask route
    return {
        "tag_context_result": (1, 0),
        "attribute_context_result": (1, 1),
        "encoded_variants_detected": False,
        "extracted_features": ["example_feature"]
    }