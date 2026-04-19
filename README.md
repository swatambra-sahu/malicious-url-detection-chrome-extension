# Malicious URL Detection Chrome Extension

## 📌 Project Overview

This project is a **Chrome Extension for detecting malicious URLs** using machine learning. It analyzes URLs in real-time and classifies them into:

* Phishing
* Malware
* Defacement
* Benign

The system supports both:

* 🌐 **Hosted backend (cloud-based API)**
* 💻 **Local backend (Flask server)**

---

## 🎯 Features

* Real-time URL classification
* Machine learning-based detection
* Dual backend support (local + hosted)
* Lightweight Chrome extension
* Fast and scalable architecture

---

## 🧠 Machine Learning Model

Models used:

* Support Vector Machine (SVM)
* Random Forest Classifier
* (Optional) XGBoost

### Feature Extraction Includes:

* URL length
* Presence of IP address
* Special characters count (`@`, `?`, `%`, etc.)
* Domain and path-based features
* Suspicious keyword detection

---

## 🌐 Backend Options

### 🔹 1. Hosted Backend (Recommended)

The extension connects to a deployed API:

```bash
https://swatambra.pythonanywhere.com
```

✔ No setup required
✔ Ready for demo and real-time use

---

### 🔹 2. Local Backend (Optional)

You can run the backend locally using Flask.

---

## 🔌 API Details

### Endpoint

```bash
POST /predict
```

### Request

```json
{
  "url": "https://example.com"
}
```

### Response

```json
{
  "prediction": "benign"
}
```

---

## 📂 Project Structure

```
Malicious-URL-Detection-Chrome-Extension/
│
├── Dataset/
│   └── malicious_phish.csv
│
├── model/
│   ├── model.pkl
│   └── label_encoder.pkl
│
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   └── background.js
│
├── loadData.py
├── app.py
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### 🔹 Step 1: Clone Repository

```bash
git clone https://github.com/your-username/malicious-url-detection-chrome-extension.git
cd malicious-url-detection-chrome-extension
```

---

## 🌐 Option A: Use Hosted Backend (Recommended)

No backend setup required.

The extension directly connects to:

```
https://swatambra.pythonanywhere.com
```

👉 Just load the extension in Chrome.

---

## 💻 Option B: Run Local Backend

### Step 1: Create Virtual Environment

```bash
python3 -m venv env
source env/bin/activate   # macOS/Linux
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Run Backend

```bash
python app.py
```

Backend will run at:

```
http://127.0.0.1:5000
```

---

### 🔹 Step 4: Configure Extension (IMPORTANT)

In `popup.js`, change API URL:

#### ✔ For hosted backend:

```javascript
fetch("https://swatambra.pythonanywhere.com/predict", {...})
```

#### ✔ For local backend:

```javascript
fetch("http://127.0.0.1:5000/predict", {...})
```

---

## 🧩 Load Chrome Extension

1. Open Google Chrome
2. Go to: `chrome://extensions/`
3. Enable **Developer Mode**
4. Click **Load unpacked**
5. Select the `extension/` folder

---

## 🚀 Usage

* Open any website
* Click on the extension
* URL is sent to backend (local or hosted)
* Displays prediction result

---

## 📊 Results

* Random Forest accuracy: ~98%
* Efficient classification of malicious URLs
* Real-time detection capability

---

## 🌍 Deployment

* Backend hosted on PythonAnywhere
* Extension communicates via REST API
* Supports both local and cloud-based execution

---

## 🔐 Future Enhancements

* Real-time warning popups
* Threat severity score
* Integration with cybersecurity APIs
* Improved UI/UX

---

## 👩‍💻 Author

Swatambra Sahu

---

## 📄 License

This project is developed for academic and educational purposes.
