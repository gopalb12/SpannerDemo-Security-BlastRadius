#!/bin/bash
PROJECT_ID=$(gcloud config get-value project)
LOCATION="us"

echo "Setting up BigQuery dataset..."
bq mk --location=$LOCATION security_logs || true

echo "Creating dummy Threat Intelligence tables in BigQuery..."
bq query --use_legacy_sql=false "
CREATE OR REPLACE TABLE \`$PROJECT_ID.security_logs.threat_intel\` AS
SELECT 'Workload-A12' as compromised_workload_id, '192.168.1.5' as malicious_ip, TIMESTAMP('2023-10-27 10:00:00 UTC') as detected_at UNION ALL
SELECT 'Workload-B45' as compromised_workload_id, '10.0.0.99' as malicious_ip, TIMESTAMP('2023-10-27 10:15:00 UTC') as detected_at;
"

echo "Creating BigQuery connection to Spanner..."
# Ensure the API is enabled
gcloud services enable bigqueryconnection.googleapis.com

# Create the connection
bq mk \
  --connection \
  --location=$LOCATION \
  --connection_type=CLOUD_SPANNER \
  --properties='{"database":"projects/'$PROJECT_ID'/instances/spanner-security-demo/databases/security-graph","useParallelism":true}' \
  spanner_sec_conn || true

echo "BigQuery Setup Complete!"
echo "Note: In a real environment, you grant the connection's Service Account 'Spanner Database Reader' access."
