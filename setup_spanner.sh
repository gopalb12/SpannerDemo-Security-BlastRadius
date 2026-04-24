#!/bin/bash
set -e

PROJECT_ID=$(gcloud config get-value project)
if [ -z "$PROJECT_ID" ]; then
    echo "Error: No active gcloud project set. Please run 'gcloud config set project [YOUR_PROJECT_ID]'"
    exit 1
fi
INSTANCE_ID="spanner-security-demo"
DATABASE_ID="security-graph"

echo "Setting project to $PROJECT_ID..."
gcloud config set project $PROJECT_ID

echo "Enabling Spanner API..."
gcloud services enable spanner.googleapis.com

echo "Creating Spanner Instance..."
echo "Creating Spanner Instance..."
# Check if instance exists. If it does and is NOT Enterprise, recreate.
EXISTS=$(gcloud spanner instances describe $INSTANCE_ID --project=$PROJECT_ID --format="value(name)" 2>/dev/null || echo "false")
if [ "$EXISTS" != "false" ]; then
    EDITION=$(gcloud spanner instances describe $INSTANCE_ID --project=$PROJECT_ID --format="value(edition)" 2>/dev/null)
    if [ "$EDITION" = "ENTERPRISE" ] || [ "$EDITION" = "ENTERPRISE_PLUS" ]; then
        echo "Instance $INSTANCE_ID already exists and is $EDITION edition. Skipping recreation."
    else
        echo "Instance $INSTANCE_ID exists but is $EDITION. Deleting to ensure Enterprise..."
        gcloud spanner instances delete $INSTANCE_ID --project=$PROJECT_ID --quiet
        gcloud spanner instances create $INSTANCE_ID \
            --config=regional-us-central1 \
            --description="Security Blast Radius Demo" \
            --edition=ENTERPRISE \
            --nodes=1 \
            --project=$PROJECT_ID
    fi
else
    # Instance does not exist
    gcloud spanner instances create $INSTANCE_ID \
        --config=regional-us-central1 \
        --description="Security Blast Radius Demo" \
        --edition=ENTERPRISE \
        --nodes=1 \
        --project=$PROJECT_ID
fi

echo "Creating Spanner Database..."
if ! gcloud spanner databases describe $DATABASE_ID --instance=$INSTANCE_ID --project=$PROJECT_ID > /dev/null 2>&1; then
    # We will apply the DDL here
    # Note: Spanner CLI or Python client is better for complex DDL with Graph.
    # However, gcloud allows passing a DDL file.
    
    # We need to read the schema.ddl content, but gcloud expects a list of statements.
    # Spanner Graph DDL is supported in `gcloud spanner databases create` via `--ddl-file` or `--ddl`.
    # Let's try passing the file directly.
    
    echo "Applying Schema..."
    gcloud spanner databases create $DATABASE_ID \
        --instance=$INSTANCE_ID \
        --ddl-file=schema.ddl \
        --project=$PROJECT_ID
else
    echo "Database $DATABASE_ID already exists. Creating tables if not exist..."
    # If DB exists, update schema. This is trickier with gcloud and extensive DDL.
    # Better to assume fresh creation for this demo script or let user handle it.
    echo "Skipping DDL application on existing DB. If you need to reset, delete the DB."
fi

echo "Setup complete. Now creating Python environment..."
PYTHON_BIN="python3"
if [ ! -d "venv" ]; then
    "$PYTHON_BIN" -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt

echo "To generate data, run: python generate_data.py --project $PROJECT_ID --instance $INSTANCE_ID --database $DATABASE_ID"
