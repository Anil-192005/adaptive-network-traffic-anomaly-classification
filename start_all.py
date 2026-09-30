"""
start_all.py - Simultaneous launcher for FastAPI backend and Streamlit frontend.
"""

import subprocess
import sys
import time

def run():
    print("=" * 60)
    print("Starting Adaptive Network Traffic Anomaly Classifier")
    print("=" * 60)

    # 1. Start FastAPI Backend
    print("[1/2] Launching FastAPI Backend on http://127.0.0.1:8000 ...")
    backend_proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn", "api:app",
        "--host", "127.0.0.1", "--port", "8000"
    ])

    # Give backend a moment to bind port
    time.sleep(2)

    # 2. Start Streamlit Frontend
    print("[2/2] Launching Streamlit Frontend on http://localhost:8501 ...")
    frontend_proc = subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", "app.py",
        "--server.port", "8501", "--server.headless", "true",
        "--browser.gatherUsageStats", "false"
    ])

    print("\n[SUCCESS] Both services are running simultaneously:")
    print("  ● Streamlit Web UI : http://localhost:8501")
    print("  ● FastAPI Swagger  : http://127.0.0.1:8000/docs")
    print("\nPress Ctrl+C to terminate both servers.")

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\nStopping services...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("Both services stopped.")

if __name__ == "__main__":
    run()
