import re
from bs4 import BeautifulSoup
def run_sanitizer_demo():
    html_content = "<html><script>alert('XSS')</script></html>"
    sanitized_html, alert = sanitizehtmlresponse(html_content)
    print(sanitized_html, alert)
def sanitizehtmlresponse(html_content: str) -> str:
    """
    Automatically sanitizes potentially malicious HTML/JS from the HTTP response.
    Used only when deviation is detected.
    """
    soup = BeautifulSoup(html_content, 'html.parser')

    # 1. Remove or escape <script> tags
    for script_tag in soup.find_all('script'):
        script_tag.decompose()  # Remove the entire <script> block

    # 2. Remove dangerous event handlers (e.g., onclick, onmouseover)
    for tag in soup.find_all():
     for attr, val in list(tag.attrs.items()):  # Use items() here
        if attr.lower().startswith("on"):
            del tag[attr]

    # 3. Neutralize javascript: URLs
    for tag in soup.find_all(href=True):
        if tag['href'].strip().lower().startswith("javascript:"):
            tag['href'] = "#"

    # 4. Sanitize dangerous inline JS functions
    dangerous_js_patterns = [
        r'eval\s*\(', r'document\.write\s*\(', r'setTimeout\s*\(', r'setInterval\s*\(',
        r'innerHTML\s*=', r'location\.href\s*='
    ]

    html_str = str(soup)
    for pattern in dangerous_js_patterns:
        html_str = re.sub(pattern, '/* sanitized */', html_str, flags=re.IGNORECASE)

    return html_str
