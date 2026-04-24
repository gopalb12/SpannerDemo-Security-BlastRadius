#!/bin/bash
set -e

echo "============================================="
echo "Spanner Graph Demo - One-Click Setup & Run"
echo "============================================="

# 1. Setup Spanner
echo "[1/5] Setting up Spanner instance and database..."
chmod +x setup_spanner.sh
./setup_spanner.sh

# 2. Setup BigQuery
echo "[2/5] Setting up BigQuery dataset and connection..."
chmod +x setup_bigquery.sh
./setup_bigquery.sh

# 3. Generate Data
echo "[3/5] Generating sample data..."
source venv/bin/activate

PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "Error: No active gcloud project found."
    exit 1
fi

export GOOGLE_CLOUD_PROJECT="$PROJECT_ID"
python generate_data.py --project "$PROJECT_ID" --instance spanner-security-demo --database security-graph

# 4. Sync BigQuery with Spanner Data
echo "[4/5] Syncing BigQuery threat intel with Spanner graph..."
python update_bq_from_spanner.py

# 5. Run UI
echo "[5/5] Launching UI..."
chmod +x run_ui.sh
./run_ui.sh
