# Spanner Graph Security & Blast Radius Demo

This project demonstrates how **Google Cloud Spanner Graph** can solve the "Scale vs. Relationship" trade-off for Security ISVs. It models a **Global Identity & Asset Blast Radius Map** to unify Inventory, Identity, and Vulnerability data into a single queryable graph.

## Use Case: Real-time Blast Radius Attribution

We model a graph with:
- **Nodes**: `Users`, `Devices`, `Workloads` (VMs/Containers), `DataStores` (Databases/Buckets), `Vulnerabilities` (CVEs).
- **Edges**: `UserDeviceAuth`, `DeviceWorkloadLines`, `WorkloadWorkloadLines` (Lateral Movement), `UserDataAccess`, `WorkloadVuln`.

Key capabilities demonstrated:
1.  **Lateral Movement Analysis**: Tracing how a compromised Web Server can reach a Crown Jewel Database via internal hops.
2.  **Identity Risk**: Identifying which users (via their devices) have paths to critical data.
3.  **Vulnerability Impact**: Prioritizing CVE remediation based on what data is reachable from the vulnerable asset.

## Project Structure

- `schema.ddl`: Defines the Spanner Graph schema (Nodes and Edges).
- `setup_spanner.sh`: Automates the creation of the Spanner Instance, Database, and Schema.
- `generate_data.py`: Generates synthetic data (assets, identities, threats) and inserts it into Spanner.
- `app.py`: The Streamlit interactive dashboard for analysis and visualization.

## Prerequisites

- Python 3.8+
- Google Cloud SDK (`gcloud`) installed and authenticated.
- A Google Cloud Project with Billing enabled.
- **APIs Enabled**: Cloud Spanner, Cloud Run, and Cloud Build APIs must be enabled in your project.

## One-Click Run (Recommended)

To set up environment, database, generate data, and run analysis in one go:

```bash
chmod +x run.sh
./run.sh
```

## Interactive Dashboard (UI)

To visualize the graph and run queries interactively:

```bash
chmod +x run_ui.sh
./run_ui.sh
```

This launches a Streamlit dashboard where you can:
- **Visualize Blast Radius**: See the attack path from the vulnerable workload to the crown jewel.
- **Analyze Identity Risk**: View tables of users with risky access.
- **Trace Attack Paths**: Graph visualization of lateral movement.
- **Run Custom GQL**: Experiment with your own graph queries.

## Manual Steps

1.  **Clone/Open the Repository**:
    ```bash
    cd SpannerDemo-Security-BlastRadius
    ```

2.  **Configuration**:
    The scripts will automatically detect your active Google Cloud project using `gcloud config get-value project`. Ensure you have selected the correct project before running the scripts.
    
    Ensure you are authenticated:
    ```bash
    gcloud auth login
    gcloud auth application-default login
    ```

3.  **Setup Spanner Instance & Schema**:
    This script creates the instance `spanner-security-demo` and database `security-graph`.
    ```bash
    chmod +x setup_spanner.sh
    ./setup_spanner.sh
    ```

4.  **Generate Data**:
    Populate the graph with realistic synthetic data (Users, Workloads, Vulnerabilities, Edges).
    ```bash
    python generate_data.py --project [YOUR_PROJECT_ID] --instance spanner-security-demo --database security-graph
    ```

5.  **Run Analysis (The "Blast Radius" Demo)**:
    Launch the interactive dashboard to visualize attack paths and run queries.
    ```bash
    ./run_ui.sh
    ```

## Example Queries (GQL)

**Find Crown Jewels exposed by Log4Shell:**
```sql
GRAPH SecurityGraph
MATCH (v:Vulnerabilities)<-[:VULNERABLE_TO]-(w:Workloads)-[:LATERAL_MOVE*1..3]->(target:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
WHERE v.CveId = 'CVE-2021-44228' AND ds.SensitivityLevel = 'CRITICAL'
RETURN w.Name, ds.Name
```

## Optional: BigQuery Zero-ETL Scenario

This demo also includes an optional scenario to showcase querying Spanner data directly from BigQuery (Zero-ETL).

1.  **Setup BigQuery**:
    Run the setup script to create the dataset, dummy threat data, and the Spanner connection:
    ```bash
    chmod +x setup_bigquery.sh
    ./setup_bigquery.sh
    ```

2.  **Run Analysis**:
    Launch the UI (`./run_ui.sh`) and select the **"Zero-ETL Threat Hunting"** scenario to see the join across Spanner and BigQuery in action.

## Deployment to Cloud Run

You can deploy the dashboard to Google Cloud Run for a shared demo environment.

1.  **Deploy**:
    ```bash
    chmod +x deploy_cloud_run.sh
    ./deploy_cloud_run.sh
    ```
    *Note: By default, this deploys a secure, private service (`--no-allow-unauthenticated`).*

2.  **Public Deployment**:
    If you want to make the demo publicly accessible (e.g., for a shared link), pass `true` as an argument:
    ```bash
    ./deploy_cloud_run.sh true
    ```
