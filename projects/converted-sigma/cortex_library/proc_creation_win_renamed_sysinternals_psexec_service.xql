// Title: Renamed PsExec Service Execution
// ID: 51ae86a2-e2e1-4097-ad85-c46cb6851de4
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-07-21
// Tags: attack.execution
// Description: Detects suspicious launch of a renamed version of the PSEXESVC service with, which is not often used by legitimate administrators
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_name = "psexesvc.exe") and not ((action_process_image_path = "C:\\Windows\\PSEXESVC.exe")))
