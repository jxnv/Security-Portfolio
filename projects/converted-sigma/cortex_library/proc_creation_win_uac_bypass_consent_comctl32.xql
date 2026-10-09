// Title: UAC Bypass Using Consent and Comctl32 - Process
// ID: 1ca6bd18-0ba0-44ca-851c-92ed89a61085
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (actor_process_image_path endswith "\\consent.exe" and action_process_image_path endswith "\\werfault.exe" and (IntegrityLevel = "High" or IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384" or IntegrityLevel = "S-1-16-12288"))
