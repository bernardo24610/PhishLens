import streamlit as st
import pandas as pd
import joblib
import numpy as np

from pathlib import Path
from url_analyzer import get_url_features


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="PhishLens | AI Security",
    page_icon="🔍",
    layout="wide"
)


# ==========================================
# FILE PATHS
# ==========================================

BASE_DIR = Path("/mount/src/phishlens")
URL_MODEL_PATH = BASE_DIR / "phishing_model.pkl"
EMAIL_MODEL_PATH = BASE_DIR / "email_model.pkl"

st.write("Project Path:", str(BASE_DIR))
st.write("URL Model Exists:", URL_MODEL_PATH.exists())
st.write("Email Model Exists:", EMAIL_MODEL_PATH.exists())
for file in BASE_DIR.rglob("*.pkl"):
    st.write(str(file))


# ==========================================
# LOAD MODELS
# ==========================================

@st.cache_resource
def load_models():
    url_model = joblib.load(URL_MODEL_PATH)
    email_model = joblib.load(EMAIL_MODEL_PATH)
    return url_model, email_model

try:
    url_model, email_model = load_models()
    st.success("Both AI Models Loaded Successfully!")

except Exception as e:
    url_model = None
    email_model = None
    st.error(f"Model Loading Error: {e}")


# ==========================================
# CUSTOM CSS
# ==========================================

st.markdown("""
<style>

.stApp {
    background:
        radial-gradient(
            circle at 10% 10%,
            #172B46 0%,
            transparent 35%
        ),
        linear-gradient(
            135deg,
            #080F1E,
            #101B30,
            #0B1425
        );

    color: #FFFFFF;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1200px;
}

h1 {
    color: #70E1CB !important;
    font-size: 3.2rem !important;
    font-weight: 800 !important;
    text-align: center;
}

h2, h3 {
    color: #FFFFFF !important;
}

.subtitle {
    text-align: center;
    color: #AAB7C8;
    font-size: 17px;
    margin-bottom: 30px;
}

.badge {
    text-align: center;
    color: #70E1CB;
    font-size: 13px;
    letter-spacing: 3px;
    font-weight: bold;
    margin-bottom: 10px;
}

.glass-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(112,225,203,0.2);
    border-radius: 18px;
    padding: 25px;
    backdrop-filter: blur(15px);
    transition: all 0.3s ease;
    margin-bottom: 20px;
}

.glass-card:hover {
    border-color: #70E1CB;
    transform: translateY(-3px);
    box-shadow: 0 8px 30px rgba(112,225,203,0.08);
}

.feature-card {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 20px;
    text-align: center;
    transition: 0.3s;
}

.feature-card:hover {
    border-color: #70E1CB;
    background: rgba(112,225,203,0.05);
}

.stTextInput input,
.stTextArea textarea {
    background-color: #111E33 !important;
    color: white !important;
    border: 1px solid #263B55 !important;
    border-radius: 12px !important;
}

.stButton button {
    background: linear-gradient(
        90deg,
        #14B8A6,
        #6366F1
    );

    color: white;
    border: none;
    border-radius: 12px;
    height: 48px;
    font-weight: bold;
    transition: 0.3s;
}

.stButton button:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 20px rgba(20,184,166,0.3);
}

.stTabs [data-baseweb="tab-list"] {
    gap: 15px;
    background: rgba(255,255,255,0.03);
    padding: 10px;
    border-radius: 14px;
}

.stTabs [data-baseweb="tab"] {
    color: #AAB7C8;
    border-radius: 10px;
}

.stTabs [aria-selected="true"] {
    color: #70E1CB !important;
}

.stProgress > div > div {
    background: linear-gradient(
        90deg,
        #14B8A6,
        #6366F1
    );
}

.footer {
    text-align: center;
    color: #64748B;
    font-size: 13px;
    padding: 25px;
}

</style>
""", unsafe_allow_html=True)


# ==========================================
# RISK SCORE FUNCTION
# ==========================================

def get_risk_level(score):

    if score < 30:
        return "LOW RISK"

    elif score < 60:
        return "MEDIUM RISK"

    elif score < 80:
        return "HIGH RISK"

    else:
        return "CRITICAL RISK"


def get_phishing_probability(model, data, phishing_label):

    if not hasattr(model, "predict_proba"):
        return None

    probabilities = model.predict_proba(data)[0]

    classes = list(model.classes_)

    if phishing_label not in classes:
        return None

    phishing_index = classes.index(phishing_label)

    return float(probabilities[phishing_index])


# ==========================================
# RESULT DISPLAY
# ==========================================

def display_result(is_phishing, score, result_type):

    st.markdown("---")

    st.markdown(
        '<div class="badge">ANALYSIS COMPLETE</div>',
        unsafe_allow_html=True
    )

    if is_phishing:

        st.error(
            f"⚠️ {result_type} PHISHING DETECTED"
        )

    else:

        st.success(
            f"✅ {result_type} CLASSIFIED AS SAFE"
        )

    if score is not None:

        risk_level = get_risk_level(score)

        st.markdown(
            f"""
            <div class="glass-card">
                <h2 style="color:#70E1CB;text-align:center;">
                    {score:.2f}%
                </h2>

                <h3 style="text-align:center;">
                    {risk_level}
                </h3>

                <p style="text-align:center;color:#AAB7C8;">
                    Estimated phishing probability
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.progress(score / 100)

    else:

        st.warning("Probability score is not available.")

    st.caption(
        "Risk Score represents the model's estimated phishing probability, "
        "not a guarantee of actual safety."
    )


# ==========================================
# PREPARE URL FEATURES
# ==========================================

def prepare_url_features(features, model):

    # Check missing features

    missing_features = [
        key for key, value in features.items()
        if value is None
    ]

    if missing_features:
        return None, missing_features

    X = pd.DataFrame([features])

    # Match the exact training feature order

    if hasattr(model, "feature_names_in_"):

        expected_features = list(model.feature_names_in_)

        missing_columns = [
            feature for feature in expected_features
            if feature not in X.columns
        ]

        extra_columns = [
            feature for feature in X.columns
            if feature not in expected_features
        ]

        if missing_columns or extra_columns:

            raise ValueError(
                f"Feature mismatch. Missing: {missing_columns}, "
                f"Extra: {extra_columns}"
            )

        X = X[expected_features]

    return X, []


# ==========================================
# EMAIL EXPLAINABILITY
# ==========================================

def explain_email(email_text):

    try:

        vectorizer = email_model.named_steps["tfidfvectorizer"]

        classifier = email_model.named_steps["logisticregression"]

        transformed_email = vectorizer.transform([email_text])

        feature_names = vectorizer.get_feature_names_out()

        coefficients = classifier.coef_[0]

        contributions = (
            transformed_email.multiply(coefficients)
        ).toarray()[0]

        phishing_indices = np.argsort(contributions)[::-1]

        safe_indices = np.argsort(contributions)

        phishing_words = [
            feature_names[i]
            for i in phishing_indices
            if contributions[i] > 0
        ][:5]

        safe_words = [
            feature_names[i]
            for i in safe_indices
            if contributions[i] < 0
        ][:5]

        return phishing_words, safe_words

    except Exception:

        return [], []


# ==========================================
# HEADER
# ==========================================

st.markdown(
    '<div class="badge">ARTIFICIAL INTELLIGENCE • CYBERSECURITY</div>',
    unsafe_allow_html=True
)

st.title("🔍 PhishLens")

st.markdown(
    """
    <p class="subtitle">
        AI-Powered Phishing Detection System
        <br>
        Detect suspicious websites and malicious emails using Machine Learning.
    </p>
    """,
    unsafe_allow_html=True
)


# ==========================================
# FEATURE CARDS
# ==========================================

col1, col2 = st.columns(2)

with col1:

    st.markdown(
        """
        <div class="feature-card">
            <h2>🌐</h2>
            <h3>URL Analyzer</h3>
            <p style="color:#AAB7C8;">
                Detect suspicious websites using Machine Learning.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )


with col2:

    st.markdown(
        """
        <div class="feature-card">
            <h2>📧</h2>
            <h3>Email Analyzer</h3>
            <p style="color:#AAB7C8;">
                Analyze email content using Natural Language Processing.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )


st.write("")


# ==========================================
# ANALYZER TABS
# ==========================================

url_tab, email_tab = st.tabs([
    "🌐 URL Analyzer",
    "📧 Email Analyzer"
])


# ==========================================
# URL ANALYZER
# ==========================================

with url_tab:

    st.markdown(
        '<div class="glass-card">',
        unsafe_allow_html=True
    )

    st.subheader("🌐 Website Security Analysis")

    st.write(
        "Enter a website URL to analyze its phishing risk."
    )

    url = st.text_input(
        "Website URL",
        placeholder="https://example.com",
        key="url_input"
    )

    analyze_url = st.button(
        "🔍 Analyze Website",
        use_container_width=True
    )

    st.markdown("</div>", unsafe_allow_html=True)

    if analyze_url:

        if not url.strip():

            st.warning("Please enter a URL.")

        elif url_model is None:

            st.error("URL Model not loaded.")

        else:

            with st.spinner("Analyzing website..."):

                try:

                    features = get_url_features(url)

                    X, missing_features = prepare_url_features(
                        features,
                        url_model
                    )

                    with st.expander("🔎 Extracted URL Features"):

                        st.json(features)

                    if missing_features:

                        st.error(
                            "URL analysis is incomplete. "
                            "The model prediction was stopped."
                        )

                        st.write("Features that could not be extracted:")

                        for feature in missing_features:
                            st.write(f"- {feature}")

                        st.info(
                            "These features must be extracted correctly "
                            "before the model can make a reliable prediction."
                        )

                    else:

                        prediction = url_model.predict(X)[0]

                        phishing_probability = get_phishing_probability(
                            url_model,
                            X,
                            -1
                        )

                        risk_score = (
                            phishing_probability * 100
                            if phishing_probability is not None
                            else None
                        )

                        display_result(
                            prediction == -1,
                            risk_score,
                            "WEBSITE"
                        )

                except Exception as e:

                    st.error(f"URL Prediction Error: {e}")


# ==========================================
# EMAIL ANALYZER
# ==========================================

with email_tab:

    st.markdown(
        '<div class="glass-card">',
        unsafe_allow_html=True
    )

    st.subheader("📧 Email Security Analysis")

    st.write(
        "Paste an email message to detect phishing attempts."
    )

    email = st.text_area(
        "Email Content",
        placeholder="Paste your email content here...",
        height=220,
        key="email_input"
    )

    analyze_email = st.button(
        "🔍 Analyze Email",
        use_container_width=True
    )

    st.markdown("</div>", unsafe_allow_html=True)

    if analyze_email:

        if not email.strip():

            st.warning("Please enter email content.")

        elif email_model is None:

            st.error("Email Model not loaded.")

        else:

            with st.spinner("Analyzing email using AI..."):

                try:

                    prediction = email_model.predict([email])[0]

                    phishing_probability = get_phishing_probability(
                        email_model,
                        [email],
                        1
                    )

                    risk_score = (
                        phishing_probability * 100
                        if phishing_probability is not None
                        else None
                    )

                    display_result(
                        prediction == 1,
                        risk_score,
                        "EMAIL"
                    )

                    # Explainability

                    st.markdown("---")

                    st.subheader("🧠 Why This Result?")

                    phishing_words, safe_words = explain_email(email)

                    col1, col2 = st.columns(2)

                    with col1:

                        st.markdown(
                            "#### ⚠️ Phishing Indicators"
                        )

                        if phishing_words:

                            for word in phishing_words:
                                st.markdown(f"- `{word}`")

                        else:

                            st.write(
                                "No significant phishing-related "
                                "words found."
                            )

                    with col2:

                        st.markdown(
                            "#### ✅ Safe Indicators"
                        )

                        if safe_words:

                            for word in safe_words:
                                st.markdown(f"- `{word}`")

                        else:

                            st.write(
                                "No significant safe-related "
                                "words found."
                            )

                    st.caption(
                        "These words are approximate model contributions "
                        "based on TF-IDF and Logistic Regression coefficients. "
                        "They are not proof that an email is malicious or safe."
                    )

                    st.markdown("---")

                    st.subheader("🛡️ Security Recommendation")

                    if prediction == 1:

                        st.warning(
                            """
                            This email was classified as potentially phishing.

                            Avoid clicking suspicious links or sharing sensitive
                            information until the sender and message are verified.
                            """
                        )

                    else:

                        st.info(
                            """
                            This email was classified as safe by the model.

                            Always verify unexpected requests and suspicious
                            attachments. A safe prediction does not guarantee
                            that an email is legitimate.
                            """
                        )

                except Exception as e:

                    st.error(f"Email Prediction Error: {e}")


# ==========================================
# FOOTER
# ==========================================

st.markdown("---")

st.markdown(
    """
    <div class="footer">
        <p>🔍 PhishLens</p>
        <p>AI-Powered Phishing Detection System</p>
        <p>Generated by Bernardo essam</p>
    </div>
    """,
    unsafe_allow_html=True
)
