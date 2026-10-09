// Title: Amsi.DLL Loaded Via LOLBIN Process
// ID: 6ec86d9e-912e-4726-91a2-209359b999b9
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-06-01
// Tags: attack.defense-impairment
// Description: Detects loading of "Amsi.dll" by a living of the land process. This could be an indication of a "PowerShell without PowerShell" attack
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (ImageLoaded endswith "\\amsi.dll" and (action_process_image_path endswith "\\ExtExport.exe" or action_process_image_path endswith "\\odbcconf.exe" or action_process_image_path endswith "\\rundll32.exe"))
