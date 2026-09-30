@echo off
echo ====================================================
echo Starting Adaptive Network Traffic Anomaly Classifier
echo ====================================================

echo [1/2] Starting FastAPI Backend on http://127.0.0.1:8000 ...
start "FastAPI Backend" cmd /k "python -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload"

echo [2/2] Starting Streamlit Frontend on http://localhost:8501 ...
start "Streamlit Frontend" cmd /k "python -m streamlit run app.py --server.port 8501 --browser.gatherUsageStats false"

echo Both services launched in separate windows!
echo Frontend: http://localhost:8501
echo Backend API Docs: http://127.0.0.1:8000/docs
