# TelemetryLab: Detection Engineering & Telemetry Playground

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![SQLite](https://img.shields.io/badge/SQLite-3.35+-003B57.svg)](https://www.sqlite.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red.svg)](https://attack.mitre.org/)
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-Zero%20External-emerald.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**TelemetryLab** is a lightweight, portable, and git-friendly SQLite-based detection engineering playground. Built specifically for security analysts, threat hunters, and detection engineers, it provides a realistic local laboratory to model enterprise telemetry, practice SQL detections, test lifecycle rule engineering, benchmark false positive tuning, and mass-normalize schemas against **ECS** and **OCSF** standards.

---

## Key Capabilities

- **4-Pillar Enterprise Telemetry Simulator**:
  - **Endpoint**: Process trees (Sysmon Event ID 1), File modifications (Event ID 11), Network sockets (Event ID 3), Registry Run keys (Event ID 12/13).
  - **Network**: Zeek-style connection flow logs (`conn.log`), DNS queries with answers (`dns.log`), HTTP proxy transactions (`http.log`).
  - **Identity**: Windows / Okta / Azure AD authentication (Event ID 4624/4625), Logon Types, MFA flags, geo-locations.
  - **Cloud Infrastructure**: AWS CloudTrail / GCP Audit / Azure Activity logs.
- **MITRE ATT&CK Threat Scenarios Injected**:
  - `T1059.001`: Malicious PowerShell download cradles spawned by Microsoft Office.
  - `T1003.001`: OS Credential Dumping via LSASS memory dumps (`procdump64.exe`, `comsvcs.dll MiniDump`).
  - `T1110.003`: Password Spraying (multi-account authentication failures from Tor exit nodes).
  - `T1078`: Valid Accounts / Impossible Travel (anomalous foreign logins without MFA).
  - `T1071.004`: DNS Tunneling & DGA detection using Shannon Entropy.
  - `T1048`: Data Exfiltration over alternative protocols (> 1GB outbound bursts).
  - `T1070.001`: Indicator Removal (Security event logs cleared via `wevtutil.exe`).
  - `T1562.001`: Impair Defenses (AWS CloudTrail `StopLogging` tampering).
- **Custom Security SQLite UDFs**:
  - `REGEXP(pattern, text)`: High-performance regular expression matching natively in SQLite.
  - `ENTROPY(text)`: Shannon entropy calculation to detect DGAs, base64 blobs, and obfuscation.
  - `IP_IN_CIDR(ip, cidr)`: CIDR block evaluation natively in SQL (e.g. `IP_IN_CIDR(src_ip, '10.0.0.0/8')`).
- **Mass Schema Management & Normalization**:
  - 1-click **ECS (Elastic Common Schema)** and **OCSF (Open Cybersecurity Schema Framework)** presets.
  - Mass regex pattern renamer (e.g., regex `^dest_` -> `dst_` across all columns or tables).
  - Dry-run preview diffs before applying changes to the database.
  - Audit logging of all schema modifications in `schema_audit_log`.
- **Detection Engineering & Lifecycle Rule Engine**:
  - YAML / JSON rule catalog mapped to MITRE ATT&CK tactics, techniques, and severities.
  - Rule execution engine with batch testing, query latency measurement (sub-millisecond), and alert logging.
  - **Rule Tuning Workbench**: Benchmark baseline alert counts vs tuned alert counts to calculate noise reduction percentages.
- **Interactive Web UI & Code Editor**:
  - Dark-mode dashboard with CodeMirror SQL editor (syntax highlighting, line numbers, autocomplete, `Cmd+Enter` execution).
  - 1-click SQL detection query snippets and table schema explorer.
  - Real-time data grid with column filtering, sorting, and CSV/JSON export.
- **Live Stream Simulator & Flexible Ingest**:
  - Background event stream simulator streaming live telemetry events into SQLite every few seconds.
  - Ingest external CSV, JSON, or JSON Lines files with automatic schema inference.
- **100% Portable & Git-Friendly**:
  - Zero external pip dependencies — runs on standard library Python 3.10+.
  - Compact SQL dump (`seed.sql`) ready to commit to GitHub repositories without binary bloat.

---

## Quickstart

### 1. Launch the Web Playground
```bash
python3 app.py
```
This boots the server at **`http://127.0.0.1:8888`** and opens your default browser.

### 2. Headless / Terminal CLI Usage
```bash
# Initialize clean database schema
python3 cli.py init --force

# Seed 500 baseline events + MITRE ATT&CK attack scenarios
python3 cli.py seed --count 500

# Inspect tables and row counts
python3 cli.py tables

# Run all detection rules (batch test suite)
python3 cli.py run-rules

# Test a specific detection rule with tuning
python3 cli.py test-rule DET-EP-001 --tune

# Benchmark false-positive suppression / noise reduction
python3 cli.py tune-benchmark DET-EP-001

# View MITRE ATT&CK coverage matrix
python3 cli.py mitre

# Export clean SQL dump for Git commit
python3 cli.py export-dump seed.sql
```

---

## Repository Structure

```
telemetry-database/
├── app.py                      # Main entrypoint: Web UI launcher & auto-bootstrap
├── cli.py                      # Headless CLI for terminal automation
├── config.py                   # Configuration paths and SQLite WAL pragmas
├── server.py                   # Zero-dependency HTTP server & REST API
├── telemetry.db                # Active SQLite database file (WAL mode)
├── seed.sql                    # Clean, portable SQL dump for Git repository
├── core/
│   ├── database.py             # SQLite connection, schema init, UDFs (REGEXP, ENTROPY, IP_IN_CIDR)
│   ├── generator.py            # Telemetry generator (Endpoint, Network, Identity, Cloud + ATT&CK)
│   ├── schema_manager.py       # Mass column/table renaming, regex transforms, ECS/OCSF presets
│   ├── detection_engine.py     # Rule runner, batch suite, tuning benchmark, MITRE mapper
│   └── ingest.py               # CSV/JSON ingestion engine & live streaming simulator
├── rules/                      # Standalone SQL detection rules & catalog manifest
│   ├── rules_manifest.json     # Metadata catalog (ATT&CK IDs, severities, exclusions, guidance)
│   ├── 01_det-ep-001_t1059_001.sql
│   ├── 02_det-ep-002_t1003_001.sql
│   ├── 03_det-ep-003_t1070_001.sql
│   ├── 04_det-ep-004_t1547_001.sql
│   ├── 05_det-ep-005_t1059_003.sql
│   ├── 06_det-net-001_t1071_004.sql
│   ├── 07_det-net-002_t1048.sql
│   ├── 08_det-id-001_t1110_003.sql
│   ├── 09_det-id-002_t1078.sql
│   ├── 10_det-id-003_t1562_001.sql
│   └── 11_advanced_cte_process_ancestry.sql  # Recursive CTE process tree query
├── schema/
│   └── schema.sql              # Core DDL definitions and indexes
├── sample_data/                # Sample CSV and JSON data for testing import
│   ├── auth_sample.csv
│   ├── network_sample.csv
│   └── cloud_sample.json
├── web/                        # Web Application
│   ├── index.html              # Interface markup (SQL editor, rules grid, schema transformer)
│   ├── style.css               # Clean minimal dark theme styling
│   └── app.js                  # Frontend client logic & REST interactions
└── tests/
    └── test_telemetry_lab.py   # Unit & integration test suite (100% passing)
```

---

## Sample SQL Detection Queries

### 1. PowerShell Download Cradle Spawned by Office (`T1059.001`)
```sql
SELECT id, timestamp, host_name, user_name, process_name, parent_process_name, command_line
FROM endpoint_process
WHERE LOWER(parent_process_name) IN ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe')
  AND LOWER(process_name) IN ('powershell.exe', 'pwsh.exe', 'cmd.exe')
  AND (command_line REGEXP '(?i)(downloadstring|downloadfile|iex|invoke-expression|-enc|-encodedcommand)');
```

### 2. High Shannon Entropy DNS Tunneling / DGA (`T1071.004`)
```sql
SELECT id, timestamp, host_name, src_ip, query, query_length, ENTROPY(query) AS entropy_score
FROM network_dns
WHERE query_length > 25
  AND ENTROPY(query) > 3.6
  AND query NOT LIKE '%.corp.local';
```

### 3. Password Spraying Authentication Failures (`T1110.003`)
```sql
SELECT src_ip, COUNT(DISTINCT user_name) AS targeted_users, COUNT(*) AS failure_count,
       GROUP_CONCAT(DISTINCT user_name) AS user_list, MIN(timestamp) AS start_time, MAX(timestamp) AS end_time
FROM identity_auth
WHERE auth_status = 'FAILURE'
GROUP BY src_ip
HAVING COUNT(DISTINCT user_name) >= 4;
```

### 4. Advanced: Recursive Common Table Expression (CTE) for Process Trees
```sql
WITH RECURSIVE ProcessTree AS (
    SELECT id, timestamp, host_name, user_name, process_name, process_id, parent_process_id,
           parent_process_name, command_line, 0 AS depth, process_name AS tree_path
    FROM endpoint_process
    WHERE process_name IN ('powershell.exe', 'cmd.exe', 'procdump64.exe')
    
    UNION ALL
    
    SELECT p.id, p.timestamp, p.host_name, p.user_name, p.process_name, p.process_id,
           p.parent_process_id, p.parent_process_name, p.command_line, pt.depth + 1,
           p.process_name || ' -> ' || pt.tree_path
    FROM endpoint_process p
    JOIN ProcessTree pt ON p.process_id = pt.parent_process_id AND p.host_name = pt.host_name
    WHERE pt.depth < 5
)
SELECT host_name, user_name, process_id, process_name, parent_process_name, command_line, depth, tree_path
FROM ProcessTree
ORDER BY host_name, depth DESC;
```

---

## Mass Schema Transformation & Normalization

Detection engineers frequently need to adapt telemetry schema to common industry standards. TelemetryLab provides both CLI and Web UI tools for this:

```bash
# Preview 1-click ECS normalization
python3 cli.py apply-preset ECS --dry-run

# Apply ECS normalization
python3 cli.py apply-preset ECS

# Preview regex substitution across all columns (e.g., ^dest_ to dst_)
python3 cli.py mass-rename-pattern "^dest_" "dst_" --scope column --dry-run

# Mass rename explicit columns in a table
python3 cli.py mass-rename-cols endpoint_process "command_line:process_command_line,parent_process_name:parent_name"
```

All operations are audited in `schema_audit_log`:
```sql
SELECT timestamp, operation_type, target_table, old_value, new_value, status 
FROM schema_audit_log;
```

---

## Running Automated Tests

Run the test suite:
```bash
python3 -m unittest tests/test_telemetry_lab.py
```

All 7 test cases validate isolated temporary databases, UDF math, attack scenario generation, detection evaluation, schema manipulation, and dump/restore mechanics.

---

## Security Portfolio & Resume Usage

See [PORTFOLIO_GUIDE.md](PORTFOLIO_GUIDE.md) for detailed guidance on how to present this project on your GitHub profile, security resume, and technical interviews.
