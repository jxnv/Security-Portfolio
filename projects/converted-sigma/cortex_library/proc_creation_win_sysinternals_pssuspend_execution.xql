// Title: Sysinternals PsSuspend Execution
// ID: 48bbc537-b652-4b4e-bd1d-281172df448f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-23
// Tags: attack.privilege-escalation, attack.discovery, attack.persistence, attack.t1543.003
// Description: Detects usage of Sysinternals PsSuspend which can be abused to suspend critical processes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_name = "pssuspend.exe") or ((action_process_image_path endswith "\\pssuspend.exe" or action_process_image_path endswith "\\pssuspend64.exe" or action_process_image_path endswith "\\pssuspend64a.exe")))
