import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

import joblib


# Demonstration examples only.
# Label 0 = legitimate example
# Label 1 = phishing-like example

data = [
    ("https://www.google.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.microsoft.com", 0),
    ("https://www.amazon.com", 0),
    ("https://www.python.org", 0),
    ("https://www.github.com", 0),
    ("https://www.apple.com", 0),
    ("https://www.ibm.com", 0),
    ("https://www.openai.com", 0),
    ("https://www.bbc.com", 0),
    ("https://www.nasa.gov", 0),
    ("https://www.adobe.com", 0),
    ("https://www.netflix.com", 0),
    ("https://www.linkedin.com", 0),
    ("https://www.stackoverflow.com", 0),
    ("https://www.mozilla.org", 0),

    ("http://192.0.2.10/login", 1),
    ("http://198.51.100.20/verify-account", 1),
    ("http://203.0.113.15/secure-login", 1),
    ("http://login-verify.example.invalid/account", 1),
    ("http://account-update.example.invalid/confirm", 1),
    ("http://secure-login.example.invalid/password", 1),
    ("http://verify-user.example.invalid/signin", 1),
    ("http://update-account.example.invalid/login", 1),
    ("http://192.0.2.50/confirm-identity", 1),
    ("http://203.0.113.40/bank-login", 1),
    ("http://198.51.100.90/reset-password", 1),
    ("http://signin-check.example.invalid/validate", 1),
    ("http://account-security.example.invalid/verify", 1),
    ("http://192.0.2.100/update-payment", 1),
    ("http://203.0.113.200/confirm-account", 1),
    ("http://secure-verify.example.invalid/auth", 1),
]


def extract_features(url):
    from urllib.parse import urlparse
    import ipaddress

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "uses_https": int(parsed.scheme == "https"),
        "has_ip": has_ip,
        "has_at_symbol": int("@" in url),
        "has_hyphen": int("-" in hostname),
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "has_login_keyword": int(
            any(
                word in url.lower()
                for word in ["login", "signin", "verify", "password"]
            )
        ),
        "has_suspicious_path": int(
            any(
                word in parsed.path.lower()
                for word in ["confirm", "update", "secure", "reset"]
            )
        ),
    }


df = pd.DataFrame(data, columns=["url", "label"])

X = pd.DataFrame(
    [extract_features(url) for url in df["url"]]
)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

model = make_pipeline(
    SimpleImputer(strategy="median"),
    StandardScaler(),
    RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("Demonstration model training completed.")
print("Test accuracy:", round(accuracy_score(y_test, predictions), 3))
print("\nClassification report:")
print(classification_report(y_test, predictions, zero_division=0))
print("Confusion matrix:")
print(confusion_matrix(y_test, predictions))

joblib.dump(model, "phishing_model.pkl")

print("\nSaved model as phishing_model.pkl")
print("IMPORTANT: These metrics apply only to this tiny demonstration dataset.")