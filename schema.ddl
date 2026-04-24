-- Schema for Spanner Graph Blast Radius Demo (Revised)

-- Node Tables

CREATE TABLE Users (
  UserId STRING(36) NOT NULL,
  Name STRING(MAX),
  Role STRING(MAX),
  RiskScore FLOAT64,
) PRIMARY KEY (UserId);

CREATE TABLE Devices (
  DeviceId STRING(36) NOT NULL,
  Hostname STRING(MAX),
  OsType STRING(MAX),
  IpAddress STRING(MAX),
) PRIMARY KEY (DeviceId);

CREATE TABLE Workloads (
  WorkloadId STRING(36) NOT NULL,
  Name STRING(MAX),
  Type STRING(MAX), -- Container, VM, Function
  Image STRING(MAX),
) PRIMARY KEY (WorkloadId);

CREATE TABLE DataStores (
  DataStoreId STRING(36) NOT NULL,
  Name STRING(MAX),
  Type STRING(MAX), -- GCS, SQL, BigQuery
  SensitivityLevel STRING(MAX), -- HIGH, MEDIUM, LOW
) PRIMARY KEY (DataStoreId);

CREATE TABLE Vulnerabilities (
  VulnerabilityId STRING(36) NOT NULL,
  CveId STRING(MAX),
  Description STRING(MAX),
  Severity FLOAT64, -- 1.0 to 10.0
) PRIMARY KEY (VulnerabilityId);


-- Edge Tables

-- User authenticates on a Device
CREATE TABLE UserDeviceAuth (
  AuthId STRING(36) NOT NULL,
  UserId STRING(36) NOT NULL,
  DeviceId STRING(36) NOT NULL,
  AuthType STRING(MAX), -- MFA, Password, SSO
  Timestamp TIMESTAMP,
  CONSTRAINT FK_Auth_User FOREIGN KEY (UserId) REFERENCES Users (UserId),
  CONSTRAINT FK_Auth_Device FOREIGN KEY (DeviceId) REFERENCES Devices (DeviceId),
) PRIMARY KEY (AuthId);

-- Device connects to a Workload (e.g. Laptop SSH to VM)
CREATE TABLE DeviceWorkloadLines (
  ConnectionId STRING(36) NOT NULL,
  DeviceId STRING(36) NOT NULL,
  WorkloadId STRING(36) NOT NULL,
  Protocol STRING(MAX),
  CONSTRAINT FK_DW_Device FOREIGN KEY (DeviceId) REFERENCES Devices (DeviceId),
  CONSTRAINT FK_DW_Workload FOREIGN KEY (WorkloadId) REFERENCES Workloads (WorkloadId),
) PRIMARY KEY (ConnectionId);

-- Workload connects to another Workload (Lateral movement)
CREATE TABLE WorkloadWorkloadLines (
  ConnectionId STRING(36) NOT NULL,
  SourceWorkloadId STRING(36) NOT NULL,
  TargetWorkloadId STRING(36) NOT NULL,
  Protocol STRING(MAX),
  Port INT64,
  CONSTRAINT FK_WW_Source FOREIGN KEY (SourceWorkloadId) REFERENCES Workloads (WorkloadId),
  CONSTRAINT FK_WW_Target FOREIGN KEY (TargetWorkloadId) REFERENCES Workloads (WorkloadId),
) PRIMARY KEY (ConnectionId);

-- User has access to DataStore
CREATE TABLE UserDataAccess (
  AccessId STRING(36) NOT NULL,
  UserId STRING(36) NOT NULL,
  DataStoreId STRING(36) NOT NULL,
  PermissionLevel STRING(MAX), -- READ, WRITE, OWNER
  CONSTRAINT FK_UD_User FOREIGN KEY (UserId) REFERENCES Users (UserId),
  CONSTRAINT FK_UD_DataStore FOREIGN KEY (DataStoreId) REFERENCES DataStores (DataStoreId),
) PRIMARY KEY (AccessId);

-- Workload has access to DataStore (Service Account)
CREATE TABLE WorkloadDataAccess (
  AccessId STRING(36) NOT NULL,
  WorkloadId STRING(36) NOT NULL,
  DataStoreId STRING(36) NOT NULL,
  PermissionLevel STRING(MAX),
  CONSTRAINT FK_WD_Workload FOREIGN KEY (WorkloadId) REFERENCES Workloads (WorkloadId),
  CONSTRAINT FK_WD_DataStore FOREIGN KEY (DataStoreId) REFERENCES DataStores (DataStoreId),
) PRIMARY KEY (AccessId);

-- Workload is vulnerable to a specific Vulnerability (CVE)
CREATE TABLE WorkloadVuln (
  InstanceId STRING(36) NOT NULL,
  WorkloadId STRING(36) NOT NULL,
  VulnerabilityId STRING(36) NOT NULL,
  DetectedAt TIMESTAMP,
  Status STRING(MAX), -- ACTIVE, PATCHED
  CONSTRAINT FK_WV_Workload FOREIGN KEY (WorkloadId) REFERENCES Workloads (WorkloadId),
  CONSTRAINT FK_WV_Vuln FOREIGN KEY (VulnerabilityId) REFERENCES Vulnerabilities (VulnerabilityId),
) PRIMARY KEY (InstanceId);


-- Property Graph Definition (GQL Standard Syntax for Spanner)

CREATE PROPERTY GRAPH SecurityGraph
  NODE TABLES (
    Users,
    Devices,
    Workloads,
    DataStores,
    Vulnerabilities
  )
  EDGE TABLES (
    UserDeviceAuth
      SOURCE KEY (UserId) REFERENCES Users (UserId)
      DESTINATION KEY (DeviceId) REFERENCES Devices (DeviceId)
      LABEL AUTHENTICATED_ON,

    DeviceWorkloadLines
      SOURCE KEY (DeviceId) REFERENCES Devices (DeviceId)
      DESTINATION KEY (WorkloadId) REFERENCES Workloads (WorkloadId)
      LABEL CONNECTS_TO,

    WorkloadWorkloadLines
      SOURCE KEY (SourceWorkloadId) REFERENCES Workloads (WorkloadId)
      DESTINATION KEY (TargetWorkloadId) REFERENCES Workloads (WorkloadId)
      LABEL LATERAL_MOVE,

    UserDataAccess
      SOURCE KEY (UserId) REFERENCES Users (UserId)
      DESTINATION KEY (DataStoreId) REFERENCES DataStores (DataStoreId)
      LABEL HAS_PERMISSION,

    WorkloadDataAccess
      SOURCE KEY (WorkloadId) REFERENCES Workloads (WorkloadId)
      DESTINATION KEY (DataStoreId) REFERENCES DataStores (DataStoreId)
      LABEL SERVICE_ACCESS,

    WorkloadVuln
      SOURCE KEY (WorkloadId) REFERENCES Workloads (WorkloadId)
      DESTINATION KEY (VulnerabilityId) REFERENCES Vulnerabilities (VulnerabilityId)
      LABEL VULNERABLE_TO
  );
