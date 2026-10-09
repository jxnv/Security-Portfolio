// Title: PowerShell Core DLL Loaded Via Office Application
// ID: bb2ba6fb-95d4-4a25-89fc-30bb736c021a
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-01
// Tags: attack.stealth
// Description: Detects PowerShell core DLL being loaded by an Office Product
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\excel.exe" or action_process_image_path endswith "\\mspub.exe" or action_process_image_path endswith "\\outlook.exe" or action_process_image_path endswith "\\onenote.exe" or action_process_image_path endswith "\\onenoteim.exe" or action_process_image_path endswith "\\powerpnt.exe" or action_process_image_path endswith "\\winword.exe") and (ImageLoaded contains "\\System.Management.Automation.Dll" or ImageLoaded contains "\\System.Management.Automation.ni.Dll"))
