from bs4 import BeautifulSoup
import re

def javascript_sensor(html_content: str) -> bool:
    """
    Analyzes sanitized HTML content to detect presence of malicious or suspicious JavaScript.
    
    Returns True if malicious JavaScript is detected, False otherwise.
    """
    soup = BeautifulSoup(html_content, 'html.parser')

    # Check for <script> tags
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string:
            if re.search(r"alert\(|document\.cookie|eval\(|setTimeout\(|setInterval\(", script.string, re.IGNORECASE):
                return True

    # Check for suspicious inline event handlers
    for tag in soup.find_all(True):  # all tags
        for attr in tag.attrs:
            if attr.lower().startswith('on'):  # e.g., onclick, onmouseover
                return True
            if attr.lower() in ['src', 'href'] and 'javascript:' in tag.attrs[attr].lower():
                return True

    # Obfuscated content (e.g. hex, encoded <)
    if re.search(r"(\\x3C|%3C|\\u003C|&#x3c;|&lt;)", html_content, re.IGNORECASE):
        return True

    return False
