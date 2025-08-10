import requests
from bs4 import BeautifulSoup
import os
import urllib.parse

def is_event_handler(attr_name):
    return attr_name.startswith("on")

def extract_js_behavior_types(soup, base_url):
    auto_executed = []
    event_handlers = []
    js_links = []

    script_tags = soup.find_all('script')
    for idx, tag in enumerate(script_tags):
        if tag.get('src'):
            src = urllib.parse.urljoin(base_url, tag['src'])
            auto_executed.append((f"external_script_{idx+1}.js", src))
        elif tag.string:
            auto_executed.append((f"inline_script_{idx+1}.js", tag.string))

    # Event handlers like onclick, onmouseover etc.
    for tag in soup.find_all(True):  # True = all tags
        for attr, value in tag.attrs.items():
            if is_event_handler(attr):
                event_handlers.append((tag.name, attr, value))

    # JavaScript href links
    for link in soup.find_all('a', href=True):
        if link['href'].strip().lower().startswith("javascript:"):
            js_links.append(link['href'])

    return auto_executed, event_handlers, js_links

def extract_scripts_from_url(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        output_dir = "extracted_js"
        os.makedirs(output_dir, exist_ok=True)

        auto_scripts, event_scripts, js_hrefs = extract_js_behavior_types(soup, url)

        print(f"\n Auto-executed Scripts Found: {len(auto_scripts)}")
        for name, content in auto_scripts:
            path = os.path.join(output_dir, name)
            if content.startswith("http"):
                try:
                    r = requests.get(content)
                    with open(path, "wb") as f:
                        f.write(r.content)
                except Exception as e:
                    print(f"Failed to fetch {content}: {e}")
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            print(f" Saved: {path}")

        print(f"\n Event-handler Based Scripts Found: {len(event_scripts)}")
        for tag, event, js in event_scripts:
            print(f"  • <{tag}> has event '{event}' with JS: {js[:60]}...")

        print(f"\n JavaScript URLs Found: {len(js_hrefs)}")
        for href in js_hrefs:
            print(f"  • {href}")

    except Exception as e:
        print(f" Error extracting scripts from {url}: {e}")

# Example usage
if __name__ == "__main__":
    url = input("🔗 Enter website URL: ")
    extract_scripts_from_url(url)
