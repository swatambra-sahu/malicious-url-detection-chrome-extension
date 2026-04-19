# ThreatShield — Setup & Run Guide

ThreatShield is a URL threat detection system powered by a `RandomForestClassifier` trained on ~651K URLs (with stratified sampling capping each class at 100K rows) from the `malicious_phish.csv` dataset. It classifies URLs into four categories — **Benign**, **Phishing**, **Malware**, and **Defacement** — and returns a confidence score.

---

## Architecture Overview

The project consists of three components:

### Flask Backend (`app.py`)
- Serves the `/predict` API endpoint that accepts a URL and returns `result_str`, `predicted_class`, and `confidence`.
- Trains the RandomForest model at startup using the full dataset with stratified sampling.
- Includes a trusted domain whitelist for known legitimate domains (Google, Amazon, Microsoft, etc.) that bypasses ML classification and returns `benign` with 100% confidence.
- Serves the web UI via Flask's template rendering.

### Web UI (`templates/index.html`)
- A single-page application with a dark theme (`#0a0e17` background, `#00ff88` accent).
- Front-end-only login/signup flow using `localStorage` (stored under the key `ts_user`) — there is no backend authentication.
- URL scanner with scan history and result display showing predicted category and confidence.

### Chrome Extension (`popup.html`, `popup.js`, `popup.css`, `manifest.json`)
- A Manifest V3 extension named "ThreatShield" that communicates with the Flask backend's `/predict` endpoint.
- Features a matching dark theme, auto-detects the current tab's URL, and stores scan history in `chrome.storage.local`.
- Includes a 10-second fetch timeout via `AbortController` and auto-prepends `https://` to bare domain inputs.

---

## Setup & Run Instructions

### Step 1: Create a virtual environment and install dependencies

```sh
pip install virtualenv
python -m venv env
```

Activate the virtual environment:

**Windows:**
```sh
env\Scripts\activate
```

**Mac / Linux:**
```sh
source env/bin/activate
```

Install dependencies:
```sh
pip install -r requirements.txt
```

### Step 2: Run the Flask server

```sh
python app.py
```

> [!CAUTION]
> The server takes **~1–2 minutes to start** due to model training on the large dataset. Wait until the terminal displays the Flask development server URL before proceeding.

Once ready, open the web UI at: **http://127.0.0.1:5000**

### Step 3: Load the Chrome extension

1. Open your browser's extension page:
   - Chrome: `chrome://extensions/`
   - Brave: `brave://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **"Load unpacked"** and select the `Web_Extension_API` folder.
4. The ThreatShield extension will appear in your extensions list. Pin it for quick access.
5. Click the extension icon — it will auto-fill the current tab's URL. Click **"Scan URL"** or press **Enter** to scan.

---

## Known Notes

- **Startup time**: The Flask server takes ~1–2 minutes to start because the RandomForest model trains on ~651K rows at startup.
- **Bare domains**: URLs entered without a scheme (e.g., `amazon.com` instead of `https://amazon.com`) are automatically prepended with `https://` by the Chrome extension. The web UI also handles this via the backend's trusted domain whitelist, but for best results always include the scheme.
- **Login/signup**: The authentication flow in the web UI is front-end only — credentials are stored in `localStorage` under the key `ts_user`. There is no backend authentication.
- **Extension permissions**: The extension requires `tabs`, `storage`, `activeTab`, and `scripting` permissions, plus host access to `http://127.0.0.1:5000/*`.



