// Title: UAC Bypass Using ChangePK and SLUI
// ID: 503d581c-7df0-4bbe-b9be-5840c0ecc1fc
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-08-23
// Tags: attack.privilege-escalation, attack.t1548.002
// Description: Detects an UAC bypass that uses changepk.exe and slui.exe (UACMe 61)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\changepk.exe" and actor_process_image_path endswith "\\slui.exe" and (IntegrityLevel = "High" or IntegrityLevel = "System" or IntegrityLevel = "S-1-16-16384" or IntegrityLevel = "S-1-16-12288"))
