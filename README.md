# Safely – Phishing & Scam Detection Tool

Safely is a simple cybersecurity project that helps detect **phishing messages, scam text, and risky URLs**.

It was built for the **Neurix Cybersecurity Competition 2026** using Python, Streamlit, and a Chrome extension.

The main goal is:

**Help normal users understand whether a message or website is safe or dangerous.**

---

## What Safely can do

### 1. Check messages for phishing
You can paste:

- Emails  
- SMS messages  
- Suspicious text  
- Links  

Safely shows:

- Risk score (0–100)  
- Threat level → Low / Medium / High  
- Reasons why it may be unsafe  
- Safety tips  

---

### 2. Uses both rules and AI

Safely combines two methods:

**Rule-based checks**
- Suspicious words like *OTP, password, urgent*
- Requests for personal details  
- Unsafe links (HTTP, IP address, strange domains)  
- Too many capital letters or punctuation  

**Pretrained ML model**
- Understands the meaning and tone of the message  
- Helps detect new scams without obvious keywords  

---

### 3. URL checking with VirusTotal

If a message contains a link, Safely:

- Sends the URL to **VirusTotal**
- Checks if security engines marked it malicious
- Increases the risk score if the link is dangerous

---

### 4. Streamlit web app

The app includes:

- Phishing message analyzer  
- Highlighted suspicious words  
- Safety suggestions  
- Small phishing awareness quiz  

---

### 5. Chrome extension

The Chrome extension can:

- Scan the current webpage  
- Extract visible text and links  
- Show a simple risk level  

Like a **basic safety checker while browsing**.

---

## Tech Stack

- Python  
- Streamlit  
- HuggingFace transformers model  
- VirusTotal API  
- Chrome Extension (Manifest v3)  


