// Title: File Creation In Suspicious Directory By Msdt.EXE
// ID: 318557a5-150c-4c8d-b70e-a9910e199857
// Status: test
// Level: high
// Author: Vadim Varganov, Florian Roth (Nextron Systems)
// Date: 2022-08-24
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001, cve.2022-30190
// Description: Detects msdt.exe creating files in suspicious directories which could be a sign of exploitation of either Follina or Dogwalk vulnerabilities
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\msdt.exe" and (action_file_path contains "\\Desktop\\" or action_file_path contains "\\Start Menu\\Programs\\Startup\\" or action_file_path contains "C:\\PerfLogs\\" or action_file_path contains "C:\\ProgramData\\" or action_file_path contains "C:\\Users\\Public\\"))
