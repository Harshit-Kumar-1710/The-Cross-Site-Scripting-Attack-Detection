import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import random
import string
import json
from rule_generator import generate_rules  # Import the Rule Generator
# Function to create a random string token
def create_token(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))
# Example HTML and JavaScript snippets to inject as benign features
HTML_SNIPPETS = [
    "<b>test</b>", "<i>sample</i>", "<div>test</div>", "<span>safe</span>"
]

JS_SNIPPETS = [
    "console.log('benign')", "alert('safe')", "var test = 1;", "function harmless(){}"
]
def inject_benign_features(url):
    try:
        session = requests.Session()
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = soup.find_all("form")
        print(f"\nTotal forms found: {len(forms)}")

        injected_features = []  # List to store injected features for rule generation

        for index, form in enumerate(forms):
            print(f"\nTesting form #{index + 1}")

            action = form.get("action")
            method = form.get("method", "get").lower()
            target_url = urljoin(url, action)
            inputs = form.find_all("input")

            form_data = {}
            tracking_tokens = []

            for field in inputs:
                name = field.get("name")
                field_type = field.get("type", "text")

                if name:
                    token = create_token()
                    html_feature = random.choice(HTML_SNIPPETS)
                    js_feature = random.choice(JS_SNIPPETS)

                    if field_type == "email":
                        value = f"user_{token}@mail.com"
                    elif field_type == "password":
                        value = f"Pass_{token}"
                    else:
                        value = f"{html_feature} // {js_feature} /*{token}*/"

                    form_data[name] = value
                    tracking_tokens.append(token)

                    # Collecting features to generate rules
                    injected_features.append({
                        'token': token,
                        'html_feature': html_feature,
                        'js_feature': js_feature,
                        'form_field': name,
                        'field_type': field_type
                    })

            print(f"Submitting data: {form_data}")

            if method == "post":
                result = session.post(target_url, data=form_data)
            else:
                result = session.get(target_url, params=form_data)

            reflected = [tok for tok in tracking_tokens if tok in result.text]

            if reflected:
                print(f"Reflection Detected. Tokens: {reflected}")
            else:
                print("No reflection found. Inputs appear to be filtered.")

        # Call Rule Generator to create rules based on injected features
        print("\nGenerating rules based on injected features...")
        generate_rules(injected_features)  # This will call the function in rule_generator.py

    except Exception as err:
        print(f"An error occurred: {err}")

if __name__ == "__main__":
    target = input("Enter target URL: ")
    inject_benign_features(target)
