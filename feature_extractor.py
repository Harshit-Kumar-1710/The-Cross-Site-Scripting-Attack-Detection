import re
from bs4 import BeautifulSoup

def extract_js_features_from_response(html_content):
    """
    Extract JavaScript-related features from the HTTP response.
    Used during the detection phase to analyze deviations in behavior.
    """
    features = {
        'inline_scripts': 0,
        'external_scripts': 0,
        'event_handlers': 0,
        'javascript_links': 0,
        'suspicious_functions': 0
    }

    suspicious_patterns = ['eval', 'document.write', 'setTimeout', 'setInterval', 'innerHTML', 'location.href']

    soup = BeautifulSoup(html_content, 'html.parser')

    # Count inline and external scripts
    for script in soup.find_all('script'):
        if script.get('src'):
            features['external_scripts'] += 1
        else:
            features['inline_scripts'] += 1
            for pattern in suspicious_patterns:
                if pattern in script.text:
                    features['suspicious_functions'] += 1

    # Count event-handler attributes like onclick, onmouseover, etc.
    for tag in soup.find_all():
        for attr in tag.attrs:
            if attr.startswith('on'):
                features['event_handlers'] += 1

    # Count javascript: links
    for a_tag in soup.find_all('a', href=True):
        if a_tag['href'].strip().lower().startswith('javascript:'):
            features['javascript_links'] += 1

    return features

# For testing independently
if __name__ == "__main__":
    with open("sample_response.html", "r", encoding="utf-8") as f:
        html = f.read()
        extracted = extract_js_features_from_response(html)
        print("Extracted Features:", extracted)
