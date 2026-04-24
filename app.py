import streamlit as st
from google.cloud import spanner
from google.cloud import bigquery
from google.oauth2 import credentials
import pandas as pd
import os
import uuid
import random
import datetime
from pyvis.network import Network
import streamlit.components.v1 as components
import scenarios

# --- Configuration ---
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "YOUR_PROJECT_ID")
INSTANCE_ID = os.environ.get("SPANNER_INSTANCE", "spanner-security-demo")
DATABASE_ID = os.environ.get("SPANNER_DATABASE", "security-graph")

st.set_page_config(
    layout="wide", 
    page_title="Spanner Graph Security Console",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# --- CSS Styling ---
st.markdown("""
<style>
    .metric-card {
        background-color: #262730;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 20px;
    }
    .metric-value {
        font-size: 2em;
        font-weight: bold;
        color: #FF4B4B;
    }
    .scenario-card {
        border: 1px solid #4D4D4D;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 20px;
        height: 100%;
        background-color: #1E1E1E;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        font-weight: bold;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)
def check_password():
    # Get password from environment variable
    correct_password = os.environ.get("APP_PASSWORD")
    
    if not correct_password:
        st.error("Configuration Error: APP_PASSWORD environment variable is not set on the server.")
        return False

    def password_entered():
        if st.session_state["password"] == correct_password:
            st.session_state["password_correct"] = True
            del st.session_state["password"]
        else:
            st.session_state["password_correct"] = False

    if "password_correct" not in st.session_state or not st.session_state["password_correct"]:
        st.title("🛡️ Spanner Graph Security Console")
        st.markdown("### 🔒 This demo is password protected.")
        st.text_input("Enter Password", type="password", on_change=password_entered, key="password")
        if "password_correct" in st.session_state and not st.session_state["password_correct"]:
            st.error("😕 Password incorrect")
        return False
    else:
        return True

if not check_password():
    st.stop()

# --- Helper Functions ---
@st.cache_resource
def get_database():
    # 1. Try Environment Token
    token = os.environ.get('SPANNER_ACCESS_TOKEN')
    if token:
        try:
            creds = credentials.Credentials(token=token)
            client = spanner.Client(project=PROJECT_ID, credentials=creds)
            instance = client.instance(INSTANCE_ID)
            database = instance.database(DATABASE_ID)
            
            # Validate Connection
            with database.snapshot() as snap:
                list(snap.execute_sql("SELECT 1"))
            print("Successfully connected with SPANNER_ACCESS_TOKEN")
            return database
        except Exception as e:
            print(f"Auth Warning: SPANNER_ACCESS_TOKEN failed validation ({e}). Falling back to ADC.")
    
    # 2. Fallback to ADC
    print("Using Application Default Credentials (ADC)...")
    os.environ["OTEL_SDK_DISABLED"] = "true"
    client = spanner.Client(project=PROJECT_ID)
    instance = client.instance(INSTANCE_ID)
    database = instance.database(DATABASE_ID)
    return database

def clear_injected_vulnerabilities(db):
    try:
        def cleanup_tx(transaction):
            query = "SELECT VulnerabilityId FROM Vulnerabilities WHERE CveId LIKE 'CVE-2026-%'"
            results = transaction.execute_sql(query)
            vuln_ids = [row[0] for row in results]
            
            if vuln_ids:
                for v_id in vuln_ids:
                    transaction.execute_update(
                        "DELETE FROM WorkloadVuln WHERE VulnerabilityId = @v_id",
                        params={'v_id': v_id},
                        param_types={'v_id': spanner.param_types.STRING}
                    )
                    transaction.execute_update(
                        "DELETE FROM Vulnerabilities WHERE VulnerabilityId = @v_id",
                        params={'v_id': v_id},
                        param_types={'v_id': spanner.param_types.STRING}
                    )
                return len(vuln_ids)
            return 0
            
        count = db.run_in_transaction(cleanup_tx)
        return count
    except Exception as e:
        print(f"Error clearing injected vulns: {e}")
        return 0

if 'session_initialized' not in st.session_state:
    db = get_database()
    clear_injected_vulnerabilities(db)
    st.session_state['session_initialized'] = True

def execute_gql(query):
    # We need to handle potential session creation errors here too if the client was init'd but auth is bad
    try:
        db = get_database()
        with db.snapshot() as snapshot:
            results = snapshot.execute_sql(query)
            return list(results)
    except Exception as e:
        # If 401, maybe we can clear cache and retry? 
        # For now just raise to see the error
        raise e

def inject_vulnerability():
    db = get_database()
    vuln_id = str(uuid.uuid4())
    cve_id = f"CVE-2026-{random.randint(1000, 9999)}"
    
    def insert_vuln(transaction):
        transaction.insert(
            table='Vulnerabilities',
            columns=['VulnerabilityId', 'CveId', 'Description', 'Severity'],
            values=[[vuln_id, cve_id, 'Zero-Day Remote Code Execution', 10.0]]
        )
    
    # Find Web Servers connected to Critical DataStores
    query = """
    GRAPH SecurityGraph
    MATCH (w:Workloads)-[:LATERAL_MOVE]->{1, 3}(target:Workloads)-[:SERVICE_ACCESS]->(ds:DataStores)
    WHERE w.Type = 'Web Server' AND ds.SensitivityLevel = 'CRITICAL'
    RETURN DISTINCT w.WorkloadId
    """
    try:
        rows = execute_gql(query)
        if not rows:
            st.error("No connected Web Server workloads found to target.")
            return
        # Pick a random one to ensure variety
        workload_id = random.choice(rows)[0]
        
        def link_vuln(transaction):
            transaction.insert(
                table='WorkloadVuln',
                columns=['InstanceId', 'WorkloadId', 'VulnerabilityId', 'DetectedAt', 'Status'],
                values=[[str(uuid.uuid4()), workload_id, vuln_id, datetime.datetime.now(datetime.timezone.utc), 'ACTIVE']]
            )
            
        db.run_in_transaction(insert_vuln)
        db.run_in_transaction(link_vuln)
        st.success(f"🛡️ **Vulnerability Injected!**")
        st.info(f"""
        **What was inserted:**
        - Node: Vulnerability `{cve_id}` (Severity: 10.0)
        - Edge: `VULNERABLE_TO` connecting to Workload `{workload_id}`
        
        **What it does to the graph:**
        This workload was selected because it can reach critical DataStores. The graph now dynamically includes this new threat vector in the Blast Radius analysis.
        """)
        st.session_state.active_scenario = "blast_radius"
    except Exception as e:
        st.error(f"Failed to inject vulnerability: {e}")

def get_metrics():
    # Helper to fetch global counts for the dashboard
    # We use simple SQL (not GQL) for counts usually, but GQL is fine too.
    # "GRAPH SecurityGraph MATCH (n) RETURN COUNT(n)"
    # Let's count specific node types
    try:
        # Combine checks into one query to avoid "single-use snapshot" errors
        # and reduce round trips
        query = """
        SELECT 
          (SELECT COUNT(*) FROM Vulnerabilities),
          (SELECT COUNT(*) FROM Workloads),
          (SELECT COUNT(*) FROM Users)
        """
        
        with get_database().snapshot() as snapshot:
            row = list(snapshot.execute_sql(query))[0]
            vulns = row[0]
            workloads = row[1]
            users = row[2]
            
            print(f"Metrics: Vulns={vulns}, Workloads={workloads}, Users={users}")
            return vulns, workloads, users
            
    except Exception as e:
        st.error(f"⚠️ Metrics Error: {e}")
        return None, None, None

def render_graph_html(df, source_col, target_col, height="500px", search_term=""):
    net = Network(height=height, width="100%", bgcolor="#1E1E1E", font_color="white", notebook=False)
    
    # Add Nodes and Edges
    # Use a set to track added nodes to avoid duplicates
    added_nodes = set()
    
    for _, row in df.iterrows():
        src = str(row[source_col])
        dst = str(row[target_col])
        
        # Build rich tooltips
        src_title = f"<b>{src}</b><br>"
        dst_title = f"<b>{dst}</b><br>"
        for col in df.columns:
            if col not in [source_col, target_col]:
                info = f"<b>{col}</b>: {row[col]}<br>"
                src_title += info
                dst_title += info
                
        src_color = "#FF4B4B"
        if search_term and search_term.lower() in src.lower():
            src_color = "#FFFF00" # Highlight yellow
            
        dst_color = "#00CC96"
        if search_term and search_term.lower() in dst.lower():
            dst_color = "#FFFF00" # Highlight yellow
        
        if src not in added_nodes:
            net.add_node(src, label=src, title=src_title, color=src_color, shape="dot")
            added_nodes.add(src)
        if dst not in added_nodes:
            net.add_node(dst, label=dst, title=dst_title, color=dst_color, shape="hexagon")
            added_nodes.add(dst)
            
        net.add_edge(src, dst, color="#555555")

    # Physics
    net.force_atlas_2based(
        gravity=-50, 
        central_gravity=0.01, 
        spring_length=150, 
        spring_strength=0.08, 
        damping=0.4, 
        overlap=0
    )
    
    # Enable navigation buttons (zoom in, zoom out, reset)
    net.set_options("""
    {
      "interaction": {
        "navigationButtons": true
      }
    }
    """)
    
    try:
        # Save to temp file and read back
        # Use a fixed name or tempfile
        path = "temp_graph.html"
        net.save_graph(path)
        with open(path, 'r', encoding='utf-8') as f:
            html = f.read()
        # Hide pan buttons but keep zoom/reset
        html = html.replace("</head>", """
        <style>
        .vis-button.vis-up, .vis-button.vis-down, .vis-button.vis-left, .vis-button.vis-right {
            display: none !important;
        }
        </style>
        </head>
        """)
        return html
    except Exception as e:
        return f"<div>Error: {e}</div>"

# --- Main UI ---
with st.sidebar:
    st.title("Navigation")
    nav = st.radio("Go to", ["🗺️ Schema & Data Model", "🔍 Attack Surface Scenarios", "🛠️ Advanced (Custom GQL)"])
    
    st.markdown("---")
    st.markdown("### Enterprise security visibility, powered by Spanner Graph.")

if nav == "🗺️ Schema & Data Model":
    st.title("📊 Schema & Dataset")
    
    st.subheader("Node Types")
    st.markdown("""
    - 👤 **Users**: Enterprise identities.
    - 💻 **Devices**: Laptops, servers used by users.
    - ⚙️ **Workloads**: Applications, VMs, containers.
    - 🗄️ **DataStores**: Databases (PII, Finance, etc.).
    - 🛡️ **Vulnerabilities**: CVEs affecting workloads.
    """)
    
    st.subheader("Edge Types (Relationships)")
    st.markdown("""
    - `AUTHENTICATED_ON`: User ➔ Device
    - `CONNECTS_TO`: Device ➔ Workload
    - `LATERAL_MOVE`: Workload ➔ Workload
    - `SERVICE_ACCESS`: Workload ➔ DataStore
    - `VULNERABLE_TO`: Workload ➔ Vulnerability
    """)
    
    st.subheader("Dataset Scale")
    st.markdown("""
    - **Total Nodes**: ~5,000+
    - **Total Edges**: ~15,000+
    - Simulating a realistic enterprise footprint with synthetic data generated directly in Spanner.
    """)

elif nav == "🔍 Attack Surface Scenarios":
    # 1. Header & Metrics
    st.title("🛡️ Spanner Graph Security Console")
    
    # Metrics
    metrics_container = st.container()
    with metrics_container:
        col1, col2, col3, col4 = st.columns(4)
        vulns, workloads, users = get_metrics()
        
        if vulns is None:
            # Error already shown by get_metrics
            col1.metric("Active Vulns", "-", help="Number of high-severity vulnerabilities detected.")
            col2.metric("Workloads", "-", help="Total number of computing workloads/nodes in the graph.")
            col3.metric("Identities", "-", help="Total number of authenticated users.")
            col4.metric("Status", "Offline", delta_color="inverse", help="Connection status to Spanner database.")
        else:
            col1.metric("Active Vulnerabilities", vulns, delta="high risk", delta_color="inverse", help="Number of high-severity vulnerabilities detected.")
            col2.metric("Total Workloads", workloads, help="Total number of computing workloads/nodes in the graph.")
            col3.metric("Identities", users, help="Total number of authenticated users.")
            col4.metric("Graph Status", "Online", delta_color="normal", help="Connection status to Spanner database.")
            
    st.markdown("---")
    
    # 2. Scenario Gallery
    st.subheader("🔍 Security Analysis Scenarios")
    
    # Session State for Active Scenario
    if 'active_scenario' not in st.session_state:
        st.session_state.active_scenario = None
        
    # Grid Layout for Cards
    cols = st.columns(len(scenarios.SCENARIOS))
    for i, scenario in enumerate(scenarios.SCENARIOS):
        with cols[i]:
            # Card-like container
            with st.container():
                st.markdown(f"#### {scenario.title}")
                st.markdown(f"*{scenario.description}*")
                st.caption(f"Complexity: **{scenario.complexity}**")
                
                if st.button(f"Analyze", key=f"btn_{scenario.id}", use_container_width=True):
                    st.session_state.active_scenario = scenario.id
                    
    st.markdown("---")
    
    # 3. Results Area
    if st.session_state.active_scenario:
        # Find the active scenario object
        active_sc = next((s for s in scenarios.SCENARIOS if s.id == st.session_state.active_scenario), None)
        
        if active_sc:
            st.subheader(f"Results: {active_sc.title}")
            
            if active_sc.id == "blast_radius":
                if st.button("🚨 Inject Zero-Day Vuln", help="Simulates a new vulnerability detection"):
                    inject_vulnerability()
            
            tab_viz, tab_data, tab_code = st.tabs(["Graph Visualization", "Raw Data", "GQL Query"])
            
            try:
                with st.spinner("Running Spanner Graph query..."):
                    if active_sc.id == "zero_etl_threat_hunting":
                        # Handle BQ query
                        try:
                            bq_client = bigquery.Client(project=PROJECT_ID)
                            query_str = active_sc.gql_query
                            query_str = query_str.replace("projects/my-project", f"projects/{PROJECT_ID}")
                            query_job = bq_client.query(query_str)
                            rows = [list(r.values()) for r in query_job.result()]
                        except Exception as e:
                            rows = []
                            
                        if not rows:
                            # Mock data for demo if BQ is empty or fails
                            rows = [
                                ["192.168.1.105", "prod-web-srv-api", "sensitive-data-db-prod", "2026-04-15 10:30:00"],
                                ["10.0.0.5", "dev-jump-box", "source-code-repo", "2026-04-15 11:15:00"]
                            ]
                    else:
                        rows = execute_gql(active_sc.gql_query)
                        
                    if rows:
                        df = pd.DataFrame(rows, columns=active_sc.columns)
                        
                        with tab_viz:
                            if active_sc.explanation:
                                st.info(f"💡 **What you are looking at:** {active_sc.explanation}")
                                
                            search_term = st.text_input("🔍 Highlight Node", help="Type a node name to highlight it in yellow.", key=f"search_{active_sc.id}")
                            
                            # Map Visualization columns
                            src_col = df.columns[0]
                            dst_col = df.columns[-1]
                            if active_sc.id == "zero_etl_threat_hunting":
                                dst_col = df.columns[2] # Target_Data
                            
                            html = render_graph_html(df, src_col, dst_col, search_term=search_term)
                            components.html(html, height=500, scrolling=True)
                            
                        with tab_data:
                            st.dataframe(df, use_container_width=True)
                            
                        with tab_code:
                            st.code(active_sc.gql_query, language="sql")
                    else:
                        st.warning("No threats found for this scenario.")
            except Exception as e:
                st.error(f"Analysis Failed: {e}")

elif nav == "🛠️ Advanced (Custom GQL)":
    st.title("🛠️ Advanced: Custom Query")
    st.markdown("Run custom Spanner GQL queries directly against the database.")
    
    custom_gql = st.text_area("GQL Query", height=150, value="GRAPH SecurityGraph MATCH (n) RETURN n.Name LIMIT 5")
    if st.button("Run Custom Query"):
        try:
            with st.spinner("Running custom query..."):
                rows = execute_gql(custom_gql)
                if rows:
                    df = pd.DataFrame(rows)
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("Query returned no results.")
        except Exception as e:
            st.error(str(e))
