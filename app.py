import re
import ipaddress
from urllib.parse import urlparse

import joblib
import pandas as pd
import streamlit as st


# -------------------------------
# LOAD THE TRAINED ML MODEL
# -------------------------------
@st.cache_resource
def load_model():
    return joblib.load("phishing_model.pkl")


try:
    model = load_model()
    model_available = True
except Exception:
    model = None
    model_available = False


# -------------------------------
# PAGE CONFIGURATION
# -------------------------------
st.set_page_config(
    page_title="AI Phishing URL Analysis Agent",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ AI-Powered Phishing URL Analysis Agent")

st.write(
    "An educational cybersecurity agent that combines "
    "machine-learning predictions and URL analysis."
)

st.warning(
    "Prototype only. Results are estimates and must not be "
    "used as proof that a website is safe or malicious."
)


# -------------------------------
# FEATURE EXTRACTION TOOL
# Must match train_model.py
# -------------------------------
def extract_features(url):
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


# -------------------------------
# URL ANALYSIS TOOL
# -------------------------------
def analyze_url(url):
    url = url.strip()

    if not url:
        return {"valid": False, "message": "Enter a URL."}

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https") or not hostname:
            return {
                "valid": False,
                "message": "Enter a valid HTTP or HTTPS URL."
            }

        # Accessing port also detects malformed port numbers.
        _ = parsed.port

        if any(char.isspace() for char in url):
            return {
                "valid": False,
                "message": "The URL must not contain spaces."
            }

        features = {
            "URL length": len(url),
            "HTTPS used": parsed.scheme == "https",
            "IP address used as host": bool(
                extract_features(url)["has_ip"]
            ),
            "Contains @ symbol": "@" in url,
            "Contains a sensitive keyword": bool(
                re.search(
                    r"login|signin|verify|account|password",
                    url,
                    re.IGNORECASE
                )
            ),
        }

        warnings = []

        if features["IP address used as host"]:
            warnings.append("The website host is an IP address.")

        if len(url) > 100:
            warnings.append("The URL is unusually long.")

        if features["Contains @ symbol"]:
            warnings.append("The URL contains an @ symbol.")

        if features["Contains a sensitive keyword"]:
            warnings.append(
                "The URL contains a sensitive keyword."
            )

        ml_result = "Unavailable"
        ml_probability = None

        if model_available:
            feature_row = pd.DataFrame(
                [extract_features(url)]
            )

            prediction = int(model.predict(feature_row)[0])

            ml_result = (
                "Phishing-like"
                if prediction == 1
                else "Legitimate-like"
            )

            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(feature_row)[0]
                ml_probability = float(max(probabilities))

        return {
            "valid": True,
            "url": url,
            "hostname": hostname,
            "features": features,
            "warnings": warnings,
            "ml_result": ml_result,
            "ml_probability": ml_probability,
        }

    except (ValueError, UnicodeError):
        return {
            "valid": False,
            "message": "The URL could not be analyzed."
        }


# -------------------------------
# AGENT CONTROLLER
# -------------------------------
# -------------------------------
# AGENT CONTROLLER
# -------------------------------
def phishing_analysis_agent(url):
    activity_log = []

    activity_log.append(
        "Step 1: Received the URL for analysis."
    )

    result = analyze_url(url)

    if not result["valid"]:
        activity_log.append(
            "Step 2: URL validation failed."
        )
        result["activity_log"] = activity_log
        return result

    activity_log.append(
        "Step 2: URL feature analysis completed."
    )

    if model_available:
        activity_log.append(
            "Step 3: Machine-learning model prediction completed."
        )
    else:
        activity_log.append(
            "Step 3: ML model unavailable; prediction skipped."
        )

    warnings = result["warnings"]
    ml_result = result["ml_result"]

    activity_log.append(
        "Step 4: Security evidence reviewed."
    )

    if warnings or ml_result == "Phishing-like":
        recommendation = (
            "Use caution. Do not enter personal information "
            "until the link has been independently verified."
        )
    else:
        recommendation = (
            "No configured warning was found. This does not "
            "establish that the website is safe."
        )

    activity_log.append(
        "Step 5: Recommendation generated."
    )

    result["recommendation"] = recommendation
    result["activity_log"] = activity_log

    return result

# -------------------------------
# USER INTERFACE
# -------------------------------
url_input = st.text_input(
    "Enter a website URL",
    placeholder="https://example.com"
)

if st.button("🔍 Analyze URL", use_container_width=True):
    if not url_input.strip():
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Agent is analyzing the URL..."):
            result = phishing_analysis_agent(url_input)

        if not result["valid"]:
            st.error(result["message"])

        else:
            st.subheader("Analysis Report")

            st.write("**Website host:**", result["hostname"])

            st.subheader("Machine Learning Prediction")
            st.write("**Model output:**", result["ml_result"])

            if result["ml_probability"] is not None:
                st.caption(
                    "Maximum model class probability: "
                    f"{result['ml_probability']:.1%}. "
                    "This is not a calibrated probability of safety."
                )

            st.subheader("URL Features")

            for feature, value in result["features"].items():
                st.write(f"• **{feature}:** {value}")

            st.subheader("Rule-based Evidence")

            if result["warnings"]:
                for warning in result["warnings"]:
                    st.warning(warning)
            else:
                st.info("No configured warning patterns were detected.")

            st.subheader("Agent Recommendation")
            st.write(result["recommendation"])
            st.subheader("🤖 Agent Activity Log")

            with st.expander("View agent execution steps", expanded=True):
                 for step in result["activity_log"]:
                     st.write("✅", step)

            st.caption(
                "This demonstration model was trained on a tiny "
                "synthetic dataset. Its predictions are not reliable "
                "for real-world phishing detection."
            )