#!/bin/bash
set -e

# Configuration
PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "Error: No active gcloud project set. Please run 'gcloud config set project [YOUR_PROJECT_ID]'"
    exit 1
fi
INSTANCE_ID="spanner-security-demo"
DATABASE_ID="security-graph"

echo "============================================="
echo "Spanner Graph UI Launcher"
echo "============================================="

# 1. Setup Environment
PYTHON_BIN="/Users/gopalbhutada/.pyenv/versions/3.12.7/bin/python3"

if [ ! -d "venv" ]; then
    echo "[1/3] Creating Python virtual environment using $PYTHON_BIN..."
    "$PYTHON_BIN" -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt -i https://pypi.org/simple/
else
    source venv/bin/activate
    # Ensure new reqs are installed
    pip install -r requirements.txt -i https://pypi.org/simple/ --quiet
fi

# 2. Get Access Token
echo "[2/3] Authenticating..."
# Force a fresh token
SPANNER_ACCESS_TOKEN=$(gcloud auth print-access-token --quiet)
if [ -z "$SPANNER_ACCESS_TOKEN" ]; then
    echo "Error: Could not get gcloud access token. Please run 'gcloud auth login' first."
    exit 1
fi
export SPANNER_ACCESS_TOKEN
echo "Token generated successfully (Starts with: ${SPANNER_ACCESS_TOKEN:0:10}...)"

# Disable OpenTelemetry
export OTEL_SDK_DISABLED=true

# 3. Launch UI
echo "[3/3] Launching Streamlit UI..."
streamlit run app.py --server.port 8501
