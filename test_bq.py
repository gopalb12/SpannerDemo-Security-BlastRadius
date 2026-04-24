import os
from google.cloud import bigquery

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "my-project-93954-gke")
client = bigquery.Client(project=PROJECT_ID)

query = f"""
SELECT 
    ti.malicious_ip AS Malicious_IP,
    sg.CompromisedWorkload AS Compromised_Workload,
    sg.ExposedCrownJewel AS Target_Data,
    ti.detected_at AS Timestamp
FROM `security_logs.threat_intel` ti
JOIN EXTERNAL_QUERY("projects/{PROJECT_ID}/locations/us/connections/spanner_sec_conn", 
    '''
    GRAPH SecurityGraph 
    MATCH (w:Workloads)-[:LATERAL_MOVE]->(target:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
    WHERE ds.SensitivityLevel = 'CRITICAL'
    RETURN w.Name AS CompromisedWorkload, w.WorkloadId AS id, ds.Name AS ExposedCrownJewel
    '''
) sg ON ti.compromised_workload_id = sg.id
"""
print("Running query...")
try:
    results = list(client.query(query).result())
    print("Results:", results)
except Exception as e:
    print("Error:", e)
