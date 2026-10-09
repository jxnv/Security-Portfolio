// Title: Winget Admin Settings Modification
// ID: 6db5eaf9-88f7-4ed9-af7d-9ef2ad12f236
// Status: test
// Level: low
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-17
// Tags: attack.persistence, attack.defense-impairment
// Description: Detects changes to the AppInstaller (winget) admin settings. Such as enabling local manifest installations or disabling installer hash checks
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\winget.exe" and TargetObject startswith "\\REGISTRY\\A\\" and TargetObject endswith "\\LocalState\\admin_settings")
