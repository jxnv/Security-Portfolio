// Title: UAC Bypass Using DismHost
// ID: 853e74f9-9392-4935-ad3b-2e8c040dae86
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-30
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path contains "C:\\Users\\" and actor_process_image_path contains "\\AppData\\Local\\Temp\\" and actor_process_image_path contains "\\DismHost.exe") and (IntegrityLevel = "High" or IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384" or IntegrityLevel = "S-1-16-12288"))
