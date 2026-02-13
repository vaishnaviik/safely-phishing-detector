from email.mime import text
import re
from urllib.parse import urlparse
import requests
import streamlit as st
from transformers import pipeline

# ================= VIRUSTOTAL URL CHECK =================

VT_API_KEY = "2ca808482e57c65731f74c89678622d912b79c0ed155b4c003913114cb216d90"

def check_url_virustotal(url):
    """
    Checks URL reputation using VirusTotal.
    Returns:
        risk_points (int), reasons (list)
    """
    try:
        headers = {"x-apikey": VT_API_KEY}

        # First encode URL in VirusTotal format
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers
        )

        if response.status_code != 200:
            return 0, []

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            return 40, ["🚨 URL flagged as MALICIOUS by VirusTotal"]

        if suspicious > 0:
            return 25, ["⚠️ URL flagged as suspicious by VirusTotal"]

        return 0, []

    except Exception:
        return 0, []

@st.cache_resource
def load_classifier():
    return pipeline(
        "text-classification",
        model="mrm8488/bert-tiny-finetuned-sms-spam-detection"
    )


SUSPICIOUS_WORDS = [
    'urgent', 'verify', 'password', 'otp', 'bank', 'suspend', 'suspended',
    'login', 'click', 'immediately', 'account', 'security', 'update',
    'confirm', 'blocked', 'expire', 'expired', 'limited', 'unusual',
    'activity', 'restore', 'locked', 'prize', 'winner', 'congratulations',
    'claim', 'free', 'bonus', 'gift', 'reward', 'act now', 'limited time',
    'reset', 'validate', 'credentials', 'ssn', 'social security',
    'credit card', 'payment', 'invoice', 'refund', 'tax', 'irs'
]

def extract_urls(text):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def analyze_url(url):
    risk_points = 0
    reasons = []
    
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            risk_points += 15
            reasons.append("❌ URL does not use secure HTTPS")
        
        if len(url) > 75:
            risk_points += 10
            reasons.append("⚠️ Suspiciously long URL")
        
        if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
            risk_points += 20
            reasons.append("🚨 URL uses IP address instead of domain name")
        
        if re.search(r'\d', parsed.netloc):
            risk_points += 10
            reasons.append("⚠️ Domain contains numbers (suspicious)")
        
        if parsed.netloc.count('.') > 2:
            risk_points += 8
            reasons.append("⚠️ Multiple subdomains detected")
            
    except Exception:
        risk_points += 5
        reasons.append("⚠️ Suspicious URL")
    
    return risk_points, reasons

from transformers import pipeline

# Load pretrained spam/phishing classifier
classifier = load_classifier()

def ml_phishing_score(text: str):
    """
    Uses spam-detection classifier correctly.
    Returns risk points (0–50).
    """
    try:
        result = classifier(text[:512])[0]

        label = result["label"].lower()
        score = result["score"]

        if "spam" in label or "phishing" in label:
            return int(score * 50)

        return int((1 - score) * 10)

    except Exception:
        return 0

def detect_phishing(text):
    
    if not text or not text.strip():
        return {
            'risk_score': 0,
            'threat_level': 'Low',
            'reasons': ['No text provided'],
            'danger_words': [],
            'suspicious_urls': []
        }
    
    text_lower = text.lower()
    risk_score = 0
    reasons = []
    danger_words = []
    suspicious_urls = []
    
    words_found = []
    for word in SUSPICIOUS_WORDS:
        if word in text_lower:
            words_found.append(word)
    
    if words_found:
        word_points = min(len(words_found) * 5, 40)
        risk_score += word_points
        danger_words = words_found
        
        if len(words_found) >= 5:
            reasons.append(f"🚨 High concentration of suspicious words ({len(words_found)} found)")
        elif len(words_found) >= 3:
            reasons.append(f"⚠️ Multiple suspicious keywords detected ({len(words_found)} found)")
        else:
            reasons.append(f"⚠️ Suspicious keywords found: {', '.join(words_found[:3])}")
    
    urgency_phrases = ['act now', 'immediately', 'urgent', 'expires', 'limited time', 'hurry']
    urgency_count = sum(1 for phrase in urgency_phrases if phrase in text_lower)
    if urgency_count > 0:
        risk_score += urgency_count * 8
        reasons.append("⏰ Creates false sense of urgency")
    
    # 3. Check for personal information requests
    sensitive_terms = ['password', 'ssn', 'social security', 'credit card', 'bank account', 'pin']
    sensitive_found = [term for term in sensitive_terms if term in text_lower]
    if sensitive_found:
        risk_score += 15
        reasons.append("🔐 Requests sensitive personal information")
    
    # 4. Analyze URLs (heuristics + VirusTotal)
    urls = extract_urls(text)
    if urls:
        for url in urls:
            # Heuristic analysis
            url_risk, url_reasons = analyze_url(url)
            if url_risk > 0:
                risk_score += url_risk
                reasons.extend(url_reasons)
                suspicious_urls.append(url)

            # 🔥 VirusTotal reputation check
            vt_risk, vt_reasons = check_url_virustotal(url)
            if vt_risk > 0:
                risk_score += vt_risk
                reasons.extend(vt_reasons)
                if url not in suspicious_urls:
                    suspicious_urls.append(url)

    # 5. Check for grammatical red flags (basic)
    if '!!!' in text or '???' in text:
        risk_score += 5
        reasons.append("⚠️ Suspicious punctuation detected")
    
    words = text.split()
    caps_words = [w for w in words if len(w) > 3 and w.isupper()]
    if len(caps_words) > 3:
        risk_score += 8
        reasons.append("⚠️ Excessive use of capital letters")
    
    # --- ML-based phishing understanding ---
    ml_score = ml_phishing_score(text)
    risk_score += ml_score

    if ml_score > 20:
        reasons.append("🤖 AI model detected phishing-like language patterns")
    elif ml_score > 0:
        reasons.append("🤖 AI model detected mildly suspicious language")

    # 6. Cap the risk score at 100
    risk_score = min(risk_score, 100)
     
    # 7. Determine threat level
    if risk_score <= 30:
        threat_level = 'Low'
    elif risk_score <= 60:
        threat_level = 'Medium'
    else:
        threat_level = 'High'
    
    # If no reasons found but score > 0, add generic message
    if not reasons and risk_score > 0:
        reasons.append("Some suspicious patterns detected")
    
    if not reasons:
        reasons.append("✅ No obvious phishing indicators detected")
    
    return {
        'risk_score': risk_score,
        'threat_level': threat_level,
        'reasons': reasons,
        'danger_words': danger_words,
        'suspicious_urls': suspicious_urls
    }

if __name__ == "__main__":
    test_message = """
    URGENT: Your bank account has been suspended!
    Click here immediately to verify your password and login credentials:
    http://192.168.1.1/bank-verify-account-123456789
    """
    result = detect_phishing(test_message)
    print(f"Risk Score: {result['risk_score']}")
    print(f"Threat Level: {result['threat_level']}")
    print(f"Reasons: {result['reasons']}")
    print(f"Danger Words: {result['danger_words']}")