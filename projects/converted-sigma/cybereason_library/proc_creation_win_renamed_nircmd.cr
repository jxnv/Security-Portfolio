// Title: Renamed NirCmd.EXE Execution
// ID: 264982dc-dbad-4dce-b707-1e0d3e0f73d9
// Status: test
// Level: high
// Author: X__Junior (Nextron Systems)
// Date: 2024-03-11
// Tags: attack.execution, attack.stealth, attack.t1059, attack.t1202
// Description: Detects the execution of a renamed "NirCmd.exe" binary based on the PE metadata fields.
// Converted by: Sigma Universal SIEM/EDR CLI

((OriginalFileName == "NirCmd.exe") AND NOT (((Image="*\\nircmd.exe" OR Image="*\\nircmdc.exe"))))
