// Title: Sysinternals PsService Execution
// ID: 3371f518-5fe3-4cf6-a14b-2a0ae3fd8a4f
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-16
// Tags: attack.privilege-escalation, attack.discovery, attack.persistence, attack.t1543.003
// Description: Detects usage of Sysinternals PsService which can be abused for service reconnaissance and tampering
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_name = "psservice.exe") or ((action_process_image_path endswith "\\PsService.exe" or action_process_image_path endswith "\\PsService64.exe" or action_process_image_path endswith "\\PsService64a.exe")))
