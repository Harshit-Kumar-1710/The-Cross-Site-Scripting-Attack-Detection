import json
def load_rules(rules_path="rules.json"):
    try:
        with open(rules_path, "r") as f:
            rules = json.load(f)
        return rules
    except FileNotFoundError:
        print(f"Error: {rules_path} not found.")
        return []

def detect_deviation(scanned_features, rules_path="rules.json"):
    rules = load_rules(rules_path)

    # Example of how you could detect deviations
    for feature_type, features in scanned_features.items():
        print(f"Checking for deviations in {feature_type}...")

        # Check if the feature type exists in rules
        if feature_type not in rules:
            print(f"Warning: No rules found for {feature_type}.")
            continue

        feature_rules = rules[feature_type]
        
        for feature in features:
            # Check if the feature is in the rules (e.g., matching against expected behavior)
            if feature not in feature_rules:
                print(f"Potential deviation detected: {feature} not in expected rules.")
            else:
                print(f"{feature} is within expected behavior.")

def perform_attack_discovery(scanned_features, rules_path="rules.json"):
    try:
        detect_deviation(scanned_features, rules_path)
    except Exception as e:
        print(f"Error in detecting deviations: {e}")
