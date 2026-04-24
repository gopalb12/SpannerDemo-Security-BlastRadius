import argparse
import uuid
import random
from typing import List, Dict
from google.cloud import spanner
from faker import Faker

fake = Faker()

def generate_uuid() -> str:
    return str(uuid.uuid4())

def reset_database(database):
    tables = [
        'UserDeviceAuth', 'DeviceWorkloadLines', 'WorkloadWorkloadLines',
        'UserDataAccess', 'WorkloadDataAccess', 'WorkloadVuln',
        'Users', 'Devices', 'Workloads', 'DataStores', 'Vulnerabilities'
    ]
    for table in tables:
        print(f"Deleting data from {table}...")
        try:
            database.execute_partitioned_dml(f"DELETE FROM {table} WHERE true")
        except Exception as e:
            print(f"Error deleting from {table}: {e}")
            raise e

def main():
    parser = argparse.ArgumentParser(description='Generate Spanner Graph Demo Data')
    parser.add_argument('--project', required=True, help='GCP Project ID')
    parser.add_argument('--instance', required=True, help='Spanner Instance ID')
    parser.add_argument('--database', required=True, help='Spanner Database ID')
    parser.add_argument('--users', type=int, default=1000, help='Number of users to generate')
    parser.add_argument('--devices', type=int, default=1500, help='Number of devices to generate')
    parser.add_argument('--workloads', type=int, default=2000, help='Number of workloads to generate')
    parser.add_argument('--datastores', type=int, default=500, help='Number of datastores to generate')
    parser.add_argument('--reset', action='store_true', help='Reset database before generating data')
    args = parser.parse_args()

    import os
    from google.oauth2 import credentials

    creds = None
    if os.environ.get('SPANNER_ACCESS_TOKEN'):
        creds = credentials.Credentials(token=os.environ['SPANNER_ACCESS_TOKEN'])

    client = spanner.Client(project=args.project, credentials=creds)
    instance = client.instance(args.instance)
    database = instance.database(args.database)

    print(f"Connecting to Spanner: {args.project}/{args.instance}/{args.database}")

    if args.reset:
        reset_database(database)


    # Generate Data
    users = []
    devices = []
    workloads = []
    datastores = []
    vulns = []

    # 1. Users
    roles = ['Admin', 'Developer', 'Analyst', 'Executive']
    for _ in range(args.users):
        users.append({
            'UserId': generate_uuid(),
            'Name': fake.name(),
            'Role': random.choice(roles),
            'RiskScore': round(random.uniform(0, 10), 1)
        })
    print(f"Generated {len(users)} Users.")

    # 2. Devices
    os_types = ['Windows', 'MacOS', 'Linux']
    for _ in range(args.devices):
        devices.append({
            'DeviceId': generate_uuid(),
            'Hostname': fake.hostname(),
            'OsType': random.choice(os_types),
            'IpAddress': fake.ipv4()
        })
    print(f"Generated {len(devices)} Devices.")

    # 3. Workloads
    wl_types = ['Web Server', 'API Gateway', 'Backend Service', 'Batch Job', 'Database Proxy']
    for _ in range(args.workloads):
        workloads.append({
            'WorkloadId': generate_uuid(),
            'Name': f"{random.choice(['prod', 'dev', 'stage'])}-{fake.word()}-{random.choice(['srv', 'db', 'api'])}",
            'Type': random.choice(wl_types),
            'Image': f"gcr.io/my-org/{fake.word()}:{random.choice(['v1', 'v2', 'latest'])}"
        })
    print(f"Generated {len(workloads)} Workloads.")

    # 4. DataStores (Crown Jewels)
    ds_types = ['Cloud SQL', 'BigQuery', 'Cloud Storage']
    sensitivities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    # Explicitly create a Crown Jewel
    crown_jewel = {
        'DataStoreId': generate_uuid(),
        'Name': 'customer-pii-db-prod',
        'Type': 'Cloud SQL',
        'SensitivityLevel': 'CRITICAL'
    }
    datastores.append(crown_jewel)
    
    for _ in range(args.datastores - 1):
        datastores.append({
            'DataStoreId': generate_uuid(),
            'Name': f"{fake.word()}-db",
            'Type': random.choice(ds_types),
            'SensitivityLevel': random.choices(sensitivities, weights=[4, 3, 2, 1])[0]
        })
    print(f"Generated {len(datastores)} DataStores.")

    # 5. Vulnerabilities
    cves = [
        {'id': 'CVE-2021-44228', 'desc': 'Log4Shell RCE', 'sev': 10.0},
        {'id': 'CVE-2017-5638', 'desc': 'Apache Struts RCE', 'sev': 9.8},
        {'id': 'CVE-2023-1234', 'desc': 'Kernel Privilege Escalation', 'sev': 7.8},
        {'id': 'CVE-2022-22965', 'desc': 'Spring4Shell', 'sev': 9.8},
        {'id': 'CVE-2019-11043', 'desc': 'PHP-FPM RCE', 'sev': 8.5}
    ]
    for cve in cves:
        vulns.append({
            'VulnerabilityId': generate_uuid(),
            'CveId': cve['id'],
            'Description': cve['desc'],
            'Severity': cve['sev']
        })
    print(f"Generated {len(vulns)} Vulnerabilities.")

    # Prepare Edges
    user_device_auth = []
    device_workload_lines = []
    workload_workload_lines = []
    user_data_access = []
    workload_data_access = []
    workload_vulns = []

    # Logic: Create a Blast Radius Path
    # Vulnerable Workload (Web Server) -> Lateral Move -> Backend -> Access -> Crown Jewel

    # Find a Web Server
    web_servers = [w for w in workloads if w['Type'] == 'Web Server']
    if not web_servers:
        web_servers = [workloads[0]] # fallback
    vuln_ws = web_servers[0]

    # Assign Log4Shell to this Web Server
    log4shell = [v for v in vulns if v['CveId'] == 'CVE-2021-44228'][0]
    
    workload_vulns.append({
        'InstanceId': generate_uuid(),
        'WorkloadId': vuln_ws['WorkloadId'],
        'VulnerabilityId': log4shell['VulnerabilityId'],
        'DetectedAt': fake.date_time_this_year(),
        'Status': 'ACTIVE'
    })

    # Pick a Backend Service
    backends = [w for w in workloads if w['Type'] == 'Backend Service' and w['WorkloadId'] != vuln_ws['WorkloadId']]
    if not backends:
        backends = [workloads[1]] # fallback
    target_backend = backends[0]

    # Create Lateral Movement Path: Web Server -> Backend
    workload_workload_lines.append({
        'ConnectionId': generate_uuid(),
        'SourceWorkloadId': vuln_ws['WorkloadId'],
        'TargetWorkloadId': target_backend['WorkloadId'],
        'Protocol': 'GRPC',
        'Port': 8080
    })

    # Grant Backend access to Crown Jewel
    workload_data_access.append({
        'AccessId': generate_uuid(),
        'WorkloadId': target_backend['WorkloadId'],
        'DataStoreId': crown_jewel['DataStoreId'],
        'PermissionLevel': 'READ_WRITE'
    })

    print("Created specific Blast Radius path: WebServer(Vuln) -> Backend -> CrownJewel")

    # Random noise edges
    # Auth
    for u in users:
        # User authenticates to 1-2 devices
        my_devices = random.sample(devices, k=random.randint(1, 2))
        for d in my_devices:
            user_device_auth.append({
                'AuthId': generate_uuid(),
                'UserId': u['UserId'],
                'DeviceId': d['DeviceId'],
                'AuthType': 'SSO',
                'Timestamp': fake.date_time_this_month()
            })
            
            # User accesses some data stores
            if u['Role'] in ['Admin', 'Developer']:
                 my_stores = random.sample(datastores, k=random.randint(0, 2))
                 for ds in my_stores:
                     user_data_access.append({
                         'AccessId': generate_uuid(),
                         'UserId': u['UserId'],
                         'DataStoreId': ds['DataStoreId'],
                         'PermissionLevel': 'READ'
                     })

    # Device -> Workload (Developer access)
    for d in devices:
        if random.random() > 0.7:
             target = random.choice(workloads)
             device_workload_lines.append({
                 'ConnectionId': generate_uuid(),
                 'DeviceId': d['DeviceId'],
                 'WorkloadId': target['WorkloadId'],
                 'Protocol': 'SSH'
             })

    # Workload -> Workload (Mesh)
    for w in workloads:
        # Each workload connects to 0-3 other workloads
        targets = random.sample(workloads, k=random.randint(0, 3))
        for t in targets:
            if t['WorkloadId'] == w['WorkloadId']: continue
            workload_workload_lines.append({
                'ConnectionId': generate_uuid(),
                'SourceWorkloadId': w['WorkloadId'],
                'TargetWorkloadId': t['WorkloadId'],
                'Protocol': 'HTTP',
                'Port': 80
            })

    # Workload -> DataStore
    for w in workloads:
        if random.random() > 0.8:
            ds = random.choice(datastores)
            workload_data_access.append({
                'AccessId': generate_uuid(),
                'WorkloadId': w['WorkloadId'],
                'DataStoreId': ds['DataStoreId'],
                'PermissionLevel': 'READ'
            })

    # Vulnerabilities
    for w in workloads:
        if random.random() > 0.9: # 10% chance
            v = random.choice(vulns)
            workload_vulns.append({
                'InstanceId': generate_uuid(),
                'WorkloadId': w['WorkloadId'],
                'VulnerabilityId': v['VulnerabilityId'],
                'DetectedAt': fake.date_time_this_month(),
                'Status': random.choice(['ACTIVE', 'PATCHED'])
            })
    
    print(f"Prepared {len(user_device_auth)} Auths, {len(device_workload_lines)} Device-Workload, {len(workload_workload_lines)} Workload-Workload, {len(workload_data_access)} Service Access.")

    # Perform Batch Insert
    def insert_in_batches(table, columns, data, batch_size=500):
        if not data:
            return
        keys = columns
        values = [[item[k] for k in keys] for item in data]
        
        for i in range(0, len(values), batch_size):
            batch = values[i:i+batch_size]
            print(f"Inserting {len(batch)} rows into {table}...")
            try:
                database.run_in_transaction(lambda tx: tx.insert(table=table, columns=keys, values=batch))
            except Exception as e:
                print(f"Error inserting into {table}: {e}")
                raise e

    try:
        insert_in_batches('Users', list(users[0].keys()), users)
        insert_in_batches('Devices', list(devices[0].keys()), devices)
        insert_in_batches('Workloads', list(workloads[0].keys()), workloads)
        insert_in_batches('DataStores', list(datastores[0].keys()), datastores)
        insert_in_batches('Vulnerabilities', list(vulns[0].keys()), vulns)
        
        insert_in_batches('UserDeviceAuth', list(user_device_auth[0].keys()), user_device_auth)
        insert_in_batches('DeviceWorkloadLines', list(device_workload_lines[0].keys()), device_workload_lines)
        insert_in_batches('WorkloadWorkloadLines', list(workload_workload_lines[0].keys()), workload_workload_lines)
        insert_in_batches('UserDataAccess', list(user_data_access[0].keys()), user_data_access)
        insert_in_batches('WorkloadDataAccess', list(workload_data_access[0].keys()), workload_data_access)
        insert_in_batches('WorkloadVuln', list(workload_vulns[0].keys()), workload_vulns)
        
        print("All data inserted successfully!")
    except Exception as e:
        print(f"Batch insertion failed: {e}")


if __name__ == '__main__':
    main()
