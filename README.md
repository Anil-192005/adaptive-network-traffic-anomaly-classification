# Adaptive Network Traffic Anomaly Classification

An end-to-end, zero-cost, full-stack machine learning application for real-time network flow telemetry inspection and cyber threat detection. Built using foundational machine learning algorithms (Logistic Regression, KNN, Decision Trees) without relying on heavy deep-learning frameworks or commercial/paid APIs.

---

## 🏗️ Architecture Overview

The system is decoupled into two independent layers communicating via a RESTful API:

```
[ User / Cyber Analyst ]
           │
           ▼
[ Streamlit Web App (app.py) ]  (Port 8501)
           │
      HTTP POST JSON
           │
           ▼
[ FastAPI Backend Service (api.py) ]  (Port 8000)
           │
           ▼
[ Scikit-Learn Pipeline (model_pipeline.pkl) ]
(StandardScaler + OneHotEncoder + Classifier)
           │
           ▼
[ Risk Assessment & Probability Response ]
```

---

## 📁 Repository Structure

```
ml final project/
├── requirements.txt      # Open-source Python dependencies
├── train.py              # ML pipeline (data synthesis/loading, leakage-free preprocessing, foundational models, evaluation, export)
├── api.py                # FastAPI REST backend service with /predict, /batch-predict, /health, /metrics
├── app.py                # Streamlit frontend user interface with preset scenarios & telemetry input form
├── paper_draft.md        # Publication-grade technical research paper draft (14 required sections)
├── model_pipeline.pkl    # Serialized end-to-end trained model pipeline artifact
├── model_metadata.json   # Exported evaluation metrics, confusion matrices, and feature schema
├── network_traffic.csv   # Synthesized/loaded benchmark network-flow dataset
└── README.md             # Project documentation and execution instructions
```

---

## 🚀 Setup & Execution Guide

### 1. Install Dependencies
Ensure Python 3.10+ is installed, then install the required open-source packages:
```bash
pip install -r requirements.txt
```

### 2. Train and Evaluate Models
Execute `train.py` to clean data, train foundational models (Logistic Regression, KNN, Decision Tree), evaluate against test splits, and export the best model artifact:
```bash
python train.py
```
*Note: If no local CSV dataset is provided, `train.py` automatically synthesizes a benchmark network-flow dataset (`network_traffic.csv`) modeled after standard intrusion datasets like CIC-IDS2017 and NSL-KDD.*

### 3. Launch FastAPI Backend Service
Start the REST backend server:
```bash
uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive Swagger API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- Benchmark Metrics: [http://127.0.0.1:8000/metrics](http://127.0.0.1:8000/metrics)

### 4. Launch Streamlit Frontend User Interface
In a separate terminal window, launch the interactive user interface:
```bash
streamlit run app.py
```
The application will open in your browser at [http://localhost:8501](http://localhost:8501).

---

## 🔍 Features & Capabilities

- **Zero-Cost ML Pipeline:** Uses foundational scikit-learn algorithms with no commercial APIs or GPU requirements.
- **Leakage-Free Preprocessing:** Standard scaling and One-Hot encoding are fit strictly on the training partition within a unified scikit-learn `Pipeline`.
- **Telemetry Validation:** Validates duration, packet counts, byte volumes, protocols (`TCP`, `UDP`, `ICMP`), services (`HTTP`, `HTTPS`, `DNS`, `SSH`, `FTP`, etc.), and TCP flags (`SF`, `S0`, `REJ`, `RSTO`).
- **Cyber Risk Scoring:** Computes risk tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and calibrated anomaly probabilities.
- **Interactive Scenarios:** Includes preset one-click attack profiles (TCP SYN Flood, Port Scan, Data Exfiltration) and normal browsing profiles.
- **Comprehensive Evaluation:** Measures Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrix.
