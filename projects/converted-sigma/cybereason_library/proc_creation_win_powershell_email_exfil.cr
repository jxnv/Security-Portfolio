// Title: Email Exifiltration Via Powershell
// ID: 312d0384-401c-4b8b-abdf-685ffba9a332
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems),  Azure-Sentinel (idea)
// Date: 2022-09-09
// Tags: attack.exfiltration
// Description: Detects email exfiltration via powershell cmdlets
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") AND (CommandLine contains "Add-PSSnapin" AND CommandLine contains "Get-Recipient" AND CommandLine contains "-ExpandProperty" AND CommandLine contains "EmailAddresses" AND CommandLine contains "SmtpAddress" AND CommandLine contains "-hidetableheaders"))
