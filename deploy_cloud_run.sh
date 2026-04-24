#!/bin/bash
set -e

# Configuration
PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "Error: No active gcloud project set. Please run 'gcloud config set project [YOUR_PROJECT_ID]'"
    exit 1
fi
REGION="us-central1"
SERVICE_NAME="spanner-security-demo"
SA_NAME="spanner-demo-sa"
INSTANCE_ID="spanner-security-demo"
DATABASE_ID="security-graph"

echo "======================================================"
echo "Deploying Spanner Graph Demo to Cloud Run"
echo "======================================================"

# 1. Enable Services
echo "[1/5] Enabling Cloud Run and Cloud Build APIs..."
# Skipping service enablement as user may not have permission. Assuming they are already enabled.
# gcloud services enable run.googleapis.com cloudbuild.googleapis.com --project=$PROJECT_ID

# 2. Create Service Account
SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe $SA_EMAIL --project=$PROJECT_ID > /dev/null 2>&1; then
    echo "[2/5] Creating Service Account $SA_NAME..."
    gcloud iam service-accounts create $SA_NAME \
        --display-name="Spanner Demo Service Account" \
        --project=$PROJECT_ID
    echo "Waiting 15 seconds for service account to propagate..."
    sleep 15
else
    echo "[2/5] Service Account $SA_NAME already exists."
fi

# 3. Grant Permissions
echo "[3/5] Granting Spanner Database User role to Service Account..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/spanner.databaseUser" > /dev/null

# 4. Deploy to Cloud Run
echo "[4/5] Building and Deploying to Cloud Run (this may take a few minutes)..."
# Check if public access is requested (passed as first argument)
ALLOW_UNAUTH=${1:-false}

if [ "$ALLOW_UNAUTH" = "true" ]; then
    AUTH_FLAG="--allow-unauthenticated"
    echo "⚠️ WARNING: Deploying publicly accessible service!"
else
    AUTH_FLAG="--no-allow-unauthenticated"
fi

gcloud run deploy $SERVICE_NAME \
    --source . \
    --region $REGION \
    --project $PROJECT_ID \
    --service-account $SA_EMAIL \
    --set-env-vars SPANNER_INSTANCE="$INSTANCE_ID",SPANNER_DATABASE="$DATABASE_ID" \
    $AUTH_FLAG \
    --quiet

# 5. Output URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --format 'value(status.url)' --project $PROJECT_ID)

echo "======================================================"
echo "Deployment Complete!"
echo "URL: $SERVICE_URL"
echo "======================================================"
echo "NOTE: This service is publicly accessible (--allow-unauthenticated)."
echo "To restrict access, run:"
echo "  gcloud run services remove-iam-policy-binding $SERVICE_NAME --region=$REGION --member=allUsers --role=roles/run.invoker"
echo "  gcloud run services add-iam-policy-binding $SERVICE_NAME --region=$REGION --member=user:EMAIL --role=roles/run.invoker"
