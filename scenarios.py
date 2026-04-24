from dataclasses import dataclass
from typing import List, Callable, Dict, Any, Tuple
import pandas as pd

@dataclass
class GraphScenario:
    id: str
    title: str
    description: str
    complexity: str  # Low, Medium, High
    gql_query: str
    # Map raw rows to (Source, Target, EdgeLabel) for visualization
    # Function signature: (row) -> (source_id, source_label, target_id, target_label, edge_text)
    viz_mapper: Callable[[pd.Series], Tuple[str, str, str, str, str]]
    columns: List[str]
    explanation: str = ""

def map_blast_radius(row):
    # Row: [Compromised Workload, CVE, Description, Exposed Crown Jewel]
    src = f"{row['Compromised Workload']}\n({row['CVE']})"
    dst = row['Exposed Crown Jewel']
    return (src, "Workload", dst, "DataStore", "EXPOSES")

def map_identity_risk(row):
    # Row: [User, Device, Entry Workload, Target Data]
    # This is a multi-hop path. We can visualize the full chain or just start/end.
    # For a simple 2-node graph, we might want to show User -> Target
    # But ideally we show the full path: User -> Device -> Workload -> Target
    # This mapper might need to return a list of edges? 
    # For now, let's keep it simple: User -> Target. 
    # Or, the UI needs to handle multi-edge generation if we want full path.
    # Let's return the primary relationship we care about.
    return (row['User'], "User", row['Target Data'], "DataStore", "ACCESSES")

def map_lateral_movement(row):
    # Row: [Entry Point, Target]
    return (row['Entry Point'], "Workload", row['Target'], "DataStore", "LATERAL_MOVE")

def map_threat_hunting(row):
    # Row: [Malicious IP, Compromised Workload, Target Data, Timestamp]
    # We will visualize IP -> Workload -> DataStore
    return (row['Malicious_IP'], "ThreatActor", row['Compromised_Workload'], "Workload", "ATTACKED")

SCENARIOS = [
    GraphScenario(
        id="blast_radius",
        title="🔥 Blast Radius Analysis",
        description="Identify Critical DataStores exposed by high-severity vulnerabilities (e.g., Log4Shell) via lateral movement paths.",
        complexity="High",
        gql_query="""
        GRAPH SecurityGraph
        MATCH (v:Vulnerabilities)<-[:VULNERABLE_TO]-(w:Workloads)-[:LATERAL_MOVE]->{1, 3}(target:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
        WHERE v.Severity >= 9.0 AND ds.SensitivityLevel = 'CRITICAL'
        RETURN DISTINCT w.Name AS CompromisedWorkload, v.CveId, v.Description, ds.Name AS ExposedCrownJewel
        """,
        viz_mapper=map_blast_radius,
        columns=["Compromised Workload", "CVE", "Description", "Exposed Crown Jewel"],
        explanation="This graph shows the potential impact of a vulnerability. It maps from a compromised workload (with a high-severity CVE) through lateral movement paths to critical data stores.\n\n- **🔴 Red Node**: Compromised Workload\n- **🟢 Green Node**: Exposed Crown Jewel (DataStore)\n- **🔗 Edges**: Access paths"
    ),
    GraphScenario(
        id="data_exfiltration_dspm",
        title="🗄️ Data Security Posture (DSPM)",
        description="Perform reverse lineage tracing: Start at a critical 'Crown Jewel' Database and walk backwards up the graph to find all identities/devices with indirect structural access.",
        complexity="Medium",
        gql_query="""
        GRAPH SecurityGraph
        MATCH (u:Users)-[:AUTHENTICATED_ON]->(d:Devices)-[:CONNECTS_TO]->(w:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
        WHERE ds.SensitivityLevel = 'CRITICAL'
        RETURN DISTINCT ds.Name AS TargetData, w.Name AS EntryWorkload, d.Hostname AS Device, u.Name AS User
        """,
        viz_mapper=map_identity_risk,
        columns=["Target Data", "Entry Workload", "Device", "User"],
        explanation="This graph shows the path from users to critical data stores. It helps identify which users and devices have access to sensitive databases.\n\n- **🔴 Red Node**: Target Data (Crown Jewel)\n- **🟢 Green Node**: User with access\n- **🔗 Edges**: Access paths"
    ),
    GraphScenario(
        id="zero_trust_bypass",
        title="🚫 Zero Trust Policy & Access Topologies",
        description="Trace multi-hop routing paths (User -> Device -> Gateway -> Backend) to detect compromised devices bypassing Zero Trust policies to reach sensitive data.",
        complexity="Medium",
        gql_query="""
        GRAPH SecurityGraph
        MATCH (u:Users)-[:AUTHENTICATED_ON]->(d:Devices)-[:CONNECTS_TO]->(w:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
        WHERE ds.SensitivityLevel = 'CRITICAL'
        RETURN DISTINCT u.Name AS User, d.Hostname AS Device, w.Name AS EntryWorkload, ds.Name AS TargetData
        """,
        viz_mapper=map_identity_risk,
        columns=["User", "Device", "Entry Workload", "Target Data"],
        explanation="This graph traces multi-hop routing paths to detect compromised devices bypassing Zero Trust policies.\n\n- **🔴 Red Node**: User\n- **🟢 Green Node**: Target Data (Crown Jewel)\n- **🔗 Edges**: Access paths"
    ),
    GraphScenario(
        id="network_segmentation",
        title="🌐 Network Segmentation & Attack Surface Risk",
        description="Traverse virtual/physical configurations (e.g. firewall rules, transit gateways) to mathematically prove whether a path exists from the public Internet to the Crown Jewels.",
        complexity="Medium",
        gql_query="""
        GRAPH SecurityGraph
        MATCH (w:Workloads)-[:LATERAL_MOVE]->{1, 4}(target:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
        WHERE w.Type = 'Web Server' AND ds.SensitivityLevel = 'CRITICAL'
        RETURN w.Name AS EntryPoint, ds.Name AS Target
        LIMIT 20
        """,
        viz_mapper=map_lateral_movement,
        columns=["Entry Point", "Target"],
        explanation="This graph shows paths from entry-point workloads (like Web Servers) to critical data stores, helping visualize the attack surface.\n\n- **🔴 Red Node**: Entry Point Workload\n- **🟢 Green Node**: Target DataStore\n- **🔗 Edges**: Attack paths"
    ),
    GraphScenario(
        id="zero_etl_threat_hunting",
        title="🕵️ XDR Telemetry Correlation (Zero-ETL)",
        description="JOIN petabytes of endpoint/network telemetry residing in BigQuery directly with live Spanner Graph topologies in a single federated query.",
        complexity="High",
        gql_query="""
        -- Run this in BigQuery to federate into Spanner Graph
        SELECT 
          ti.malicious_ip AS Malicious_IP,
          sg.CompromisedWorkload AS Compromised_Workload,
          sg.ExposedCrownJewel AS Target_Data,
          ti.detected_at AS Timestamp
        FROM `security_logs.threat_intel` ti
        JOIN EXTERNAL_QUERY("projects/my-project/locations/us/connections/spanner_sec_conn", 
          '''
          GRAPH SecurityGraph 
          MATCH (w:Workloads)-[:LATERAL_MOVE]->(target:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
          WHERE ds.SensitivityLevel = 'CRITICAL'
          RETURN w.Name AS CompromisedWorkload, w.WorkloadId AS id, ds.Name AS ExposedCrownJewel
          '''
        ) sg ON ti.compromised_workload_id = sg.id;
        """,
        viz_mapper=map_threat_hunting,
        columns=["Malicious_IP", "Compromised_Workload", "Target_Data", "Timestamp"],
        explanation="This graph correlates BigQuery network telemetry (malicious IPs) with Spanner graph data to show active lateral movement paths.\n\n- **🔴 Red Node**: Malicious IP Source\n- **🟢 Green Node**: Target Data (Crown Jewel)\n- **🔗 Edges**: Correlation links"
    )
]
