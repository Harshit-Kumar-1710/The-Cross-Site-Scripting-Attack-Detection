import requests
from bs4 import BeautifulSoup
import os
import urllib.parse
from attack_discovery import perform_attack_discovery

def is_event_handler(attr_name):
    # Check if the attribute is an event handler (e.g., onclick, onload, etc.)
    return attr_name.startswith("on")

def extract_js_behavior_types(soup, base_url):
    auto_executed = []
    event_handlers = []
    js_links = []

    # Extract all <script> tags
    script_tags = soup.find_all('script')
    for idx, tag in enumerate(script_tags):
        if tag.get('src'):
            # External JS scripts
            src = urllib.parse.urljoin(base_url, tag['src'])
            auto_executed.append((f"external_script_{idx+1}.js", src))
        elif tag.string:
            # Inline JS scripts
            auto_executed.append((f"inline_script_{idx+1}.js", tag.string))

    # Check for event-handler attributes in all HTML tags
    for tag in soup.find_all(True):  # loop through all HTML tags
        for attr, value in tag.attrs.items():
            if is_event_handler(attr):
                event_handlers.append((tag.name, attr, value))

    # Detect JavaScript URLs (e.g., javascript: in href attributes)
    for link in soup.find_all('a', href=True):
        if link['href'].strip().lower().startswith("javascript:"):
            js_links.append(link['href'])

    return auto_executed, event_handlers, js_links

def extract_scripts_from_url(url):
    try:
        # Make a request to the URL and parse the HTML content
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Directory to save extracted JS files
        output_dir = "extracted_js"
        os.makedirs(output_dir, exist_ok=True)

        # Extract JavaScript behaviors (auto-executed, event handlers, JS links)
        auto_scripts, event_scripts, js_hrefs = extract_js_behavior_types(soup, url)

        # Print and save auto-executed (inline and external) scripts
        print(f"\n Auto-executed Scripts Found: {len(auto_scripts)}")
        for name, content in auto_scripts:
            path = os.path.join(output_dir, name)
            if content.startswith("http"):  # External JS
                try:
                    r = requests.get(content)
                    with open(path, "wb") as f:
                        f.write(r.content)
                except Exception as e:
                    print(f"Failed to fetch {content}: {e}")
            else:  # Inline JS
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            print(f" Saved: {path}")

        # Print detected event-handler scripts
        print(f"\n Event-handler Based Scripts Found: {len(event_scripts)}")
        for tag, event, js in event_scripts:
            print(f"  • <{tag}> has event '{event}' with JS: {js[:60]}...")

        # Print detected JavaScript URLs
        print(f"\n JavaScript URLs Found: {len(js_hrefs)}")
        for href in js_hrefs:
            print(f"  • {href}")

        #  Build the scanned features dictionary
        scanned_features = {
            "auto_executed": [content if not content.startswith("http") else f"[external] {content}" for name, content in auto_scripts],
            "event_handlers": [f"<{tag}> {event} {js}" for tag, event, js in event_scripts],
            "js_links": js_hrefs
        }

        #  Call the attack discovery module
        perform_attack_discovery(scanned_features)

    except Exception as e:
        print(f" Error extracting scripts from {url}: {e}")

# If this script is executed directly, prompt for a URL and run the extraction
if __name__ == "__main__":
    url = input(" Enter website URL: ")  # Get URL input from the user
    extract_scripts_from_url(url)
