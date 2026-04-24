import os
from google.cloud import spanner
from google.cloud import bigquery

os.environ["OTEL_SDK_DISABLED"] = "true"
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "YOUR_PROJECT_ID")
INSTANCE_ID = "spanner-security-demo"
DATABASE_ID = "security-graph"

if PROJECT_ID == "YOUR_PROJECT_ID":
    print("Error: GOOGLE_CLOUD_PROJECT environment variable not set.")
    exit(1)

spanner_client = spanner.Client(project=PROJECT_ID)
instance = spanner_client.instance(INSTANCE_ID)
database = instance.database(DATABASE_ID)

# Query Spanner for workloads with critical data access
query = """GRAPH SecurityGraph 
MATCH (w:Workloads)-[:LATERAL_MOVE]->{1,3}(target:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
WHERE ds.SensitivityLevel = 'CRITICAL'
RETURN DISTINCT w.WorkloadId AS id
LIMIT 10
"""

wids = []
with database.snapshot() as snapshot:
    results = snapshot.execute_sql(query)
    for row in results:
        wids.append(row[0])

if not wids:
    print("No vulnerable paths found in Spanner graph! Inserting dummy data.")
    # Fallback to dummy data so the BQ table isn't empty
    wids = ['Workload-A12', 'Workload-B45']

bq_client = bigquery.Client(project=PROJECT_ID)

select_parts = []
for i, wid in enumerate(wids):
    ip = f"192.168.1.{100 + i}"
    select_parts.append(f"SELECT '{wid}' as compromised_workload_id, '{ip}' as malicious_ip, TIMESTAMP('2023-10-27 10:00:00 UTC') as detected_at")

update_query = f"CREATE OR REPLACE TABLE `{PROJECT_ID}.security_logs.threat_intel` AS " + " UNION ALL ".join(select_parts)

bq_client.query(update_query).result()
print(f"BigQuery Threat Intel updated with {len(wids)} matching Spanner Workload IDs!")
