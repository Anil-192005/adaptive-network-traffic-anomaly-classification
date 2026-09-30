# Production Deployment Guide: Adaptive Network Traffic Anomaly Classification
**Free-Tier Cloud Architecture: Render (FastAPI Backend) + Streamlit Community Cloud (Frontend)**

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │        Internet User / Evaluator       │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │       Streamlit Community Cloud        │
                      │         (Frontend Web UI)              │
                      │  https://<your-app>.streamlit.app      │
                      └──────────────────┬─────────────────────┘
                                         │ HTTPS POST
                                         │ JSON Payload
                                         ▼
                      ┌────────────────────────────────────────┐
                      │           Render Web Service           │
                      │          (FastAPI REST API)            │
                      │    https://<your-api>.onrender.com     │
                      │  ┌──────────────────────────────────┐  │
                      │  │       model_pipeline.pkl         │  │
                      │  │  (Scikit-Learn Pipeline Object)  │  │
                      │  └──────────────────────────────────┘  │
                      └────────────────────────────────────────┘
```

---

## 1. Repository Setup & Git Best Practices

### Recommended Structure: Unified Root Repository
Both Render and Streamlit Community Cloud support building directly from the repository root. This keeps local development, testing, and deployment perfectly synchronized without maintaining duplicate Git repos or submodules.

```
ml-final-project/
├── .gitignore               # Excludes raw caches/data; includes model artifacts
├── render.yaml              # Render Infrastructure-as-Code Blueprint
├── requirements-api.txt     # Lightweight requirements for FastAPI backend (Render)
├── requirements-app.txt     # Frontend requirements for Streamlit Community Cloud
├── requirements.txt         # Complete local developer requirements
├── api.py                   # FastAPI REST backend service
├── app.py                   # Streamlit frontend application
├── train.py                 # Training script for model reproduction
├── model_pipeline.pkl       # CRITICAL: Serialized Scikit-learn model artifact
├── model_metadata.json      # Metadata, feature definitions, and metrics
├── paper_draft.md           # Capstone technical paper draft
└── README.md                # Project documentation
```

### Git Configuration & Pushing to GitHub

1. Initialize git and commit:
   ```bash
   git init
   git add .
   git status
   ```
   *Verify that `model_pipeline.pkl` and `model_metadata.json` are STAGED, while `network_traffic.csv` and `__pycache__` are IGNORED.*

2. Commit and push to a new GitHub repository:
   ```bash
   git commit -m "feat: complete adaptive network anomaly classification web app"
   git branch -M main
   git remote add origin https://github.com/<your-username>/adaptive-network-anomaly-detection.git
   git push -u origin main
   ```

---

## 2. Backend Deployment on Render (Web Service Free Tier)

Render offers a 100% free tier for web services with automated HTTPS certificates and continuous deployment from GitHub.

### Method A: Automated Deployment via `render.yaml` (Recommended)
Because this repository contains [`render.yaml`](./render.yaml), Render can automatically configure the service:
1. Log in to [Render.com](https://render.com) (sign up with your GitHub account).
2. Click **Blueprints** on the top menu.
3. Click **New Blueprint Instance**.
4. Select your GitHub repository.
5. Click **Apply**. Render will automatically detect the settings from `render.yaml` and deploy!

---

### Method B: Manual Click-Path on Render Dashboard
If you prefer setting it up manually:

1. Log in to [Render.com](https://render.com).
2. Click the **New +** button at the top right and select **Web Service**.
3. Under **Build and deploy from a Git repository**, click **Next**.
4. Connect your GitHub account and select your `adaptive-network-anomaly-detection` repository.
5. Fill in the deployment details:
   - **Name:** `adaptive-network-anomaly-api` (or any unique name)
   - **Region:** Choose closest to your users (e.g., *Oregon (US West)* or *Frankfurt (EU)*)
   - **Branch:** `main`
   - **Root Directory:** *(leave blank / default)*
   - **Runtime:** `Python 3`
   - **Build Command:**
     ```bash
     pip install -r requirements-api.txt
     ```
   - **Start Command:**
     ```bash
     uvicorn api:app --host 0.0.0.0 --port $PORT
     ```
   - **Instance Type:** Select **Free** ($0/month).
6. Under **Advanced** (optional environment variables):
   - Add `PYTHON_VERSION` = `3.12.0`
7. Click **Create Web Service**.
8. Wait 2–3 minutes for the build and deployment logs to show `Uvicorn running on http://0.0.0.0:xxxx`.
9. Copy your live Render API URL from the dashboard:
   `https://adaptive-network-anomaly-api.onrender.com`

---

## 3. Frontend Deployment on Streamlit Community Cloud

Streamlit Community Cloud deploys Streamlit apps directly from GitHub for free with zero server maintenance.

### Step-by-Step Click Path:
1. Log in to [share.streamlit.io](https://share.streamlit.io) (sign in with your GitHub account).
2. Click the **Create app** button (or **New app**).
3. Select **Yup, I have an app**.
4. Fill in the repository settings:
   - **Repository:** `<your-username>/adaptive-network-anomaly-detection`
   - **Branch:** `main`
   - **Main file path:** `app.py`
   - **App URL:** *(Optionally customize your subdomain, e.g., `network-anomaly-classifier`)*
5. Click **Advanced settings...** (bottom left of the modal):
   - Under **Python version**, select `3.12` or `3.11`.
   - In the **Secrets** text box, define the link to your live Render backend:
     ```toml
     BACKEND_API_URL = "https://adaptive-network-anomaly-api.onrender.com"
     ```
     *(Replace with your actual Render URL, without a trailing slash).*
6. Click **Save**, then click **Deploy!**
7. Streamlit will install packages from `requirements-app.txt` (or `requirements.txt`) and launch your application.

---

## 4. CORS & Live Integration Validation

### CORS (Cross-Origin Resource Sharing) Configuration
To ensure the Streamlit frontend (hosted on `streamlit.app`) can query the FastAPI backend (hosted on `onrender.com`) without browser cross-origin security blocks, `api.py` includes CORSMiddleware:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from Streamlit Cloud or any origin
    allow_credentials=True,
    allow_methods=["*"],  # Allows GET, POST, OPTIONS
    allow_headers=["*"],
)
```

### End-to-End Validation Checklist

#### 1. Validate the Live Render Backend
Open your browser or terminal to check the health endpoint:
```bash
curl https://<your-render-app>.onrender.com/health
```
**Expected Response (HTTP 200):**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "active_model": "Logistic Regression",
  "timestamp": "2026-09-30T10:15:00.000000+00:00"
}
```
Open interactive Swagger docs:
`https://<your-render-app>.onrender.com/docs`

#### 2. Validate the Live Streamlit Frontend
1. Open your live Streamlit URL: `https://<your-app>.streamlit.app`.
2. Observe the sidebar indicator:
   - It should display: **● Backend Connected** with active model name.
3. Test a **Normal Traffic Scenario**:
   - In the sidebar dropdown, pick **Normal: Web Browsing (HTTPS)**.
   - Click **🔍 Classify Network Flow**.
   - Verify green banner: **✅ NORMAL TRAFFIC**, Risk: **LOW**, Probability < 5%.
4. Test an **Anomaly Traffic Scenario**:
   - In the sidebar dropdown, pick **Anomaly: TCP SYN Flood Attack**.
   - Click **🔍 Classify Network Flow**.
   - Verify red banner: **🚨 ANOMALY DETECTED**, Risk: **CRITICAL**, Probability > 95%.

---

## 5. Important Free-Tier Operational Notes

> [!NOTE]
> **Render Cold Starts (Spin-down after Inactivity):**  
> On the free tier, Render automatically spins down services after 15 minutes of inactivity.  
> When the first user accesses the live Streamlit app after inactivity:
> - The initial health check may take **30 to 50 seconds** while Render spins the container back up.
> - The updated `app.py` has an extended timeout and displays a helpful notice:  
>   `"⏳ Render free-tier services spin down after 15 min of inactivity. Please allow ~30-45 seconds for initial wake-up."`
> - Once awake, subsequent requests respond in under **50 milliseconds**.
