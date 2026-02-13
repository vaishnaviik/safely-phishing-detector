import streamlit as st
import re
from phish import detect_phishing, SUSPICIOUS_WORDS

st.set_page_config(
    page_title="SafelyAI - Be Safe Online",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>

/* ===== GLOBAL TEXT VISIBILITY FIX ===== */
html, body, .stApp, [class*="css"]  {
    background-color: #020617 !important;
    color: #E2E8F0 !important;
}

/* Force all text visible */
h1, h2, h3, h4, h5, h6,
p, span, div, label, li {
    color: #E2E8F0 !important;
}

/* ===== INPUT / TEXT AREAS ===== */
textarea, input {
    background-color: #0F172A !important;
    color: #E2E8F0 !important;
    border: 1px solid #334155 !important;
}

/* ===== METRICS / CARDS ===== */
[data-testid="stMetricValue"],
[data-testid="stMetricLabel"] {
    color: #E2E8F0 !important;
}

/* ===== SAFE / WARNING / ERROR BOXES ===== */
.stSuccess {
    background-color: #064E3B !important;
    color: #D1FAE5 !important;
}

.stWarning {
    background-color: #78350F !important;
    color: #FEF3C7 !important;
}

.stError {
    background-color: #7F1D1D !important;
    color: #FECACA !important;
}

/* ===== EXPLANATION BOX (QUIZ) ===== */
div[style*="background-color: #fff3cd"] {
    background-color: #1E293B !important;
    color: #E2E8F0 !important;
    border-left: 4px solid #FACC15 !important;
}

/* ===== HIGHLIGHTED MESSAGE BOX ===== */
.highlighted-text {
    background: #0F172A !important;
    border: 1px solid #334155 !important;
    color: #E2E8F0 !important;
}

/* ===== SAFETY TIPS ===== */
.safety-tip {
    background-color: #0F172A !important;
    color: #E2E8F0 !important;
    border-left: 4px solid #22C55E !important;
    padding: 0.75rem;
    border-radius: 6px;
    margin-bottom: 6px;
}

/* ===== BUTTON TEXT ===== */
button {
    color: #FFFFFF !important;
}

/* ===== CODE BLOCKS ===== */
code, pre {
    background-color: #020617 !important;
    color: #E2E8F0 !important;
}

</style>
""", unsafe_allow_html=True)

def highlight_dangerous_words(text, danger_words):
    """Highlight suspicious words inside the message"""
    if not danger_words:
        return text
    
    highlighted = text
    sorted_words = sorted(set(danger_words), key=len, reverse=True)

    for word in sorted_words:
        pattern = re.compile(re.escape(word), re.IGNORECASE)
        highlighted = pattern.sub(
            f'<span style="background:#7F1D1D;color:#FECACA;padding:2px 6px;border-radius:4px;font-weight:bold;">⚠ {word}</span>',
            highlighted
        )

    return highlighted

def get_safety_tips(threat_level):
    """Return safety tips based on threat level"""
    tips = {
        'High': [
            "🚫 Do NOT click any links or download attachments",
            "🗑️ Delete this message immediately",
            "📧 Report this as spam/phishing to your email provider",
            "🔐 If you've already clicked links, change your passwords immediately",
            "💬 Notify your IT department or relevant authorities"
        ],
        'Medium': [
            "⚠️ Proceed with extreme caution",
            "🔍 Verify the sender's email address carefully",
            "🌐 Hover over links before clicking (don't click suspicious URLs)",
            "📞 Contact the organization directly using official contact info",
            "🔐 Never provide passwords or sensitive information"
        ],
        'Low': [
            "✅ Message appears relatively safe, but stay vigilant",
            "🔍 Always verify sender identity for important requests",
            "🔐 Never share passwords via email or text",
            "📱 Enable two-factor authentication on your accounts",
            "🎓 Continue learning about phishing techniques"
        ]
    }
    return tips.get(threat_level, tips['Low'])

# Main app
def main():
    st.title("🛡️ Safely – Be Safe Online")
    st.markdown("""
    <p style='font-size: 1.2rem; color: #666;'>
    Protect yourself from phishing attacks and online scams with AI-powered detection.
    Paste any suspicious message, email, or URL below for instant analysis.
    </p>
    """, unsafe_allow_html=True)
    
    # Create tabs
    tab1, tab2 = st.tabs(["🔍 Phishing Detector", "🎓 SafelySpidey"])
    
    with tab1:
        st.markdown("---")
        
        # Input section
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("📝 Enter Message to Analyze")
            user_input = st.text_area(
                "Paste email, message, or URL here:",
                height=200,
                placeholder="Example: URGENT! Your account will be suspended. Click here to verify immediately..."
            )
            
            analyze_button = st.button("🔍 Analyze Message", type="primary", use_container_width=True)
        
        with col2:
            st.subheader("💡 Quick Examples")
            if st.button("Example 1: Phishing Email", use_container_width=True):
                st.session_state.example_text = """URGENT: Your bank account has been suspended due to unusual activity.
                
Click here immediately to verify your login credentials and restore access:
http://secure-bank-verify123.com/login

Failure to act within 24 hours will result in permanent account closure."""
                st.rerun()
            
            if st.button("Example 2: Safe Message", use_container_width=True):
                st.session_state.example_text = """Hi there,

Thanks for your recent purchase. Your order #12345 has been shipped and will arrive in 3-5 business days.

You can track your package at: https://www.amazon.com/track

Best regards,
Customer Service Team"""
                st.rerun()
        
        # Use example text if set
        if 'example_text' in st.session_state:
            user_input = st.session_state.example_text
            del st.session_state.example_text
            st.rerun()
        
        # Analysis section
        if analyze_button and user_input:
            with st.spinner("🔎 Analyzing message for threats..."):
                result = detect_phishing(user_input)
                
                st.markdown("---")
                st.subheader("📊 Analysis Results")
                
                # Risk Score and Threat Level
                col1, col2, col3 = st.columns([1, 1, 2])
                
                with col1:
                    st.metric("Risk Score", f"{result['risk_score']}/100")
                    st.progress(result['risk_score'] / 100)
                
                with col2:
                    threat_level = result['threat_level']
                    threat_class = f"threat-{threat_level.lower()}"
                    
                    if threat_level == 'High':
                        st.markdown(f"<div class='{threat_class}'>🔴 High Risk</div>", unsafe_allow_html=True)
                    elif threat_level == 'Medium':
                        st.markdown(f"<div class='{threat_class}'>🟡 Medium Risk</div>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<div class='{threat_class}'>🟢 Low Risk</div>", unsafe_allow_html=True)
                
                with col3:
                    if result['risk_score'] >= 61:
                        st.error("⚠️ This message shows strong signs of phishing!")
                    elif result['risk_score'] >= 31:
                        st.warning("⚠️ This message has some suspicious characteristics")
                    else:
                        st.success("✅ This message appears relatively safe")
                
                # Highlighted text (Grammarly-style)
                st.markdown("---")
                st.subheader("📄 Message Analysis (Dangerous Words Highlighted)")
                
                if result['danger_words']:
                    highlighted_text = highlight_dangerous_words(user_input, result['danger_words'])
                    st.markdown(
                        f'<div class="highlighted-text">{highlighted_text}</div>',
                        unsafe_allow_html=True
                    )
                    st.caption(f"⚠️ Found {len(result['danger_words'])} suspicious keyword(s)")
                else:
                    st.markdown(
                        f'<div class="highlighted-text">{user_input}</div>',
                        unsafe_allow_html=True
                    )
                    st.caption("✅ No suspicious keywords detected")
                
                # Detailed reasons
                st.markdown("---")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("🔍 Why This Was Flagged")
                    for reason in result['reasons']:
                        st.markdown(f"• {reason}")
                    
                    if result['suspicious_urls']:
                        st.markdown("**Suspicious URLs found:**")
                        for url in result['suspicious_urls']:
                            st.code(url, language=None)
                
                with col2:
                    st.subheader("🛡️ Safety Recommendations")
                    tips = get_safety_tips(result['threat_level'])
                    for tip in tips:
                        st.markdown(f'<div class="safety-tip">{tip}</div>', unsafe_allow_html=True)
        
        elif analyze_button:
            st.warning("⚠️ Please enter some text to analyze!")
    
    # TAB 2: Awareness Quiz
    with tab2:
        st.markdown("---")
        st.subheader("🎓 Test Your Phishing Detection Skills")
        st.markdown("Can you spot the phishing attempt? Read the message below and make your choice.")

    # Quiz questions
        quiz_questions = [
            {
                "message": """Subject: Urgent Security Alert

Your PayPal account has been limited due to unusual activity.

Click here immediately to verify your identity:
http://paypal-secure-login99.com/verify

You have 24 hours before permanent suspension.""",
            "is_phishing": True,
            "explanation": """This is a PHISHING attempt! 🚨

**Warning signs:**
1. ⚠️ Creates urgency ("immediately", "24 hours")
2. 🔗 Suspicious URL (not official PayPal domain)
3. 🔐 Requests account verification via link
4. 😨 Threatens account suspension
5. 🌐 URL contains numbers (paypal...99.com)

**Real PayPal would:**
✅ Use official domain (paypal.com)
✅ Never threaten immediate suspension
✅ Let you log in through their official app/website"""
        },
        {
            "message": """Hi John,

Thank you for your order #AB-12345. Your package has been shipped via FedEx.

Tracking number: 1Z999AA10123456784

You can track your delivery at: https://www.fedex.com/track

Estimated delivery: March 15, 2024

Best regards,
Customer Service Team""",
            "is_phishing": False,
            "explanation": """This is a SAFE message! ✅

**Why it's trustworthy:**
1. ✅ Uses official HTTPS domain (fedex.com)
2. ✅ Provides specific order/tracking numbers
3. ✅ No urgency or threats
4. ✅ No request for personal information
5. ✅ Professional formatting

**Good practices demonstrated:**
• Legitimate tracking information
• Official company domain
• No suspicious links or requests"""
        }
    ]

    # Quiz state management
        if 'quiz_index' not in st.session_state:
            st.session_state.quiz_index = 0
        if 'quiz_answered' not in st.session_state:
            st.session_state.quiz_answered = False
        if 'quiz_score' not in st.session_state:
            st.session_state.quiz_score = 0
        if 'quiz_attempts' not in st.session_state:
            st.session_state.quiz_attempts = 0

        current_q = quiz_questions[st.session_state.quiz_index]

    # ===== DARK QUIZ MESSAGE BOX (FIXED) =====
        st.markdown(f"""
    <div style='background-color:#0F172A; padding:1.5rem; border-radius:8px; border:1px solid #334155; color:#E2E8F0;'>
    <p style='font-size:1.1rem; line-height:1.6; white-space:pre-wrap;'>{current_q['message']}</p>
    </div>
    """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

    # Answer buttons
        col1, col2 = st.columns(2)

        with col1:
            if st.button("✅ This is SAFE", use_container_width=True, disabled=st.session_state.quiz_answered):
                st.session_state.quiz_answered = True
                st.session_state.quiz_attempts += 1
                if not current_q['is_phishing']:
                    st.session_state.quiz_score += 1
                    st.session_state.user_answer = "Correct! ✅"
                else:
                    st.session_state.user_answer = "Incorrect ❌"

        with col2:
            if st.button("🚨 This is PHISHING", use_container_width=True, disabled=st.session_state.quiz_answered):
                st.session_state.quiz_answered = True
                st.session_state.quiz_attempts += 1
                if current_q['is_phishing']:
                    st.session_state.quiz_score += 1
                    st.session_state.user_answer = "Correct! ✅"
                else:
                    st.session_state.user_answer = "Incorrect ❌"
    # Show explanation after answer
        if st.session_state.quiz_answered:
            st.markdown("---")

            if 'user_answer' in st.session_state:
                if "Correct" in st.session_state.user_answer:
                    st.success(st.session_state.user_answer)
                else:
                    st.error(st.session_state.user_answer)

        # ===== DARK EXPLANATION BOX (FIXED) =====
            st.markdown(f"""
        <div style='background-color:#0F172A; padding:1.5rem; border-radius:8px; border-left:4px solid #FACC15; color:#E2E8F0;'>
        <h4>📚 Explanation</h4>
        <p style='white-space:pre-wrap;'>{current_q['explanation']}</p>
        </div>
        """, unsafe_allow_html=True)

        # Next question button
            if st.session_state.quiz_index < len(quiz_questions) - 1:
                if st.button("➡️ Next Question", type="primary"):
                    st.session_state.quiz_index += 1
                    st.session_state.quiz_answered = False
                    if 'user_answer' in st.session_state:
                        del st.session_state.user_answer
                    st.rerun()
            else:
                st.markdown("---")
                score_pct = (st.session_state.quiz_score / st.session_state.quiz_attempts) * 100
                st.success(f"🎉 Quiz Complete! Your score: {st.session_state.quiz_score}/{st.session_state.quiz_attempts} ({score_pct:.0f}%)")

                if st.button("🔄 Restart Quiz"):
                    st.session_state.quiz_index = 0
                    st.session_state.quiz_answered = False
                    st.session_state.quiz_score = 0
                    st.session_state.quiz_attempts = 0
                    if 'user_answer' in st.session_state:
                        del st.session_state.user_answer
                    st.rerun()

        # Display current score
        if st.session_state.quiz_attempts > 0:
            st.markdown("---")
            st.info(f"📊 Current Score: {st.session_state.quiz_score}/{st.session_state.quiz_attempts}")

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 2rem;'>
    <p>🛡️ <strong>Safely</strong> - Stay Protected Online</p>
    <p style='font-size: 0.9rem;'>Safely for Neurix 2026</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()