// Title: ServiceDll Hijack
// ID: 612e47e9-8a59-43a6-b404-f48683f45bd6
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-02-04
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects changes to the "ServiceDLL" value related to a service in the registry.
// This is often used as a method of persistence.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((TargetObject contains "\\System\\" and TargetObject contains "ControlSet" and TargetObject contains "\\Services\\") and TargetObject endswith "\\Parameters\\ServiceDll") and not (((action_process_image_path = "C:\\Windows\\system32\\lsass.exe" and TargetObject endswith "\\Services\\NTDS\\Parameters\\ServiceDll" and Details = "%%systemroot%%\\system32\\ntdsa.dll") or (action_process_image_path = "C:\\Windows\\System32\\poqexec.exe") or (Details = "C:\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintConfig.dll") or (action_process_image_path endswith "\\regsvr32.exe" and TargetObject endswith "\\Services\\PrintNotify\\Parameters\\ServiceDll" and Details startswith "C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\" and Details endswith "\\arm64\\PrintConfig.dll"))) and not ((action_process_image_path endswith "\\regsvr32.exe" and Details = "C:\\Windows\\System32\\STAgent.dll")))
