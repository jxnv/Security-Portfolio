// Title: Email Exifiltration Via Powershell
// ID: 312d0384-401c-4b8b-abdf-685ffba9a332
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems),  Azure-Sentinel (idea)
// Date: 2022-09-09
// Tags: attack.exfiltration
// Description: Detects email exfiltration via powershell cmdlets
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\powershell.exe" or action_process_image_path endswith "\\pwsh.exe") and (action_process_image_command_line contains "Add-PSSnapin" and action_process_image_command_line contains "Get-Recipient" and action_process_image_command_line contains "-ExpandProperty" and action_process_image_command_line contains "EmailAddresses" and action_process_image_command_line contains "SmtpAddress" and action_process_image_command_line contains "-hidetableheaders"))
