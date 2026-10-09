// Title: Suspicious PowerShell Download - Powershell Script
// ID: 403c2cc0-7f6b-4925-9423-bfa573bed7eb
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2017-03-05
// Tags: attack.execution, attack.t1059.001
// Description: Detects suspicious PowerShell download command
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "System.Net.WebClient") and ((ScriptBlockText contains ".DownloadFile(" or ScriptBlockText contains ".DownloadFileAsync(" or ScriptBlockText contains ".DownloadString(" or ScriptBlockText contains ".DownloadStringAsync(")))
