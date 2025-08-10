import json

# Function to generate rules from injected features
def generate_rules(injected_features):
    try:
        # Create an empty list to store the generated rules
        rules = []

        # Iterate through the injected features and create rules
        for feature in injected_features:
            rule = {
                "form_field": feature['form_field'],
                "field_type": feature['field_type'],
                "html_feature": feature['html_feature'],
                "js_feature": feature['js_feature'],
                "token": feature['token']
            }
            rules.append(rule)

        # Write the generated rules to a JSON file
        rules_path = "rules.json"
        with open(rules_path, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=4)

        print(f"Rules generated and saved to: {rules_path}")

    except Exception as e:
        print(f"Error generating rules: {e}")

if __name__ == "__main__":
    # Example feature list for testing
    injected_features = [
        {
            "form_field": "username",
            "field_type": "text",
            "html_feature": "<b>example</b>",
            "js_feature": "console.log('safe');",
            "token": "abc123"
        },
        {
            "form_field": "password",
            "field_type": "password",
            "html_feature": "<i>demo</i>",
            "js_feature": "let a = 10;",
            "token": "xyz456"
        }
    ]
    generate_rules(injected_features)
