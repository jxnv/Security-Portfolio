// Title: PowerShell Script With File Hostname Resolving Capabilities
// ID: fbc5e92f-3044-4e73-a5c6-1c4359b539de
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-05
// Tags: attack.exfiltration, attack.t1020
// Description: Detects PowerShell scripts that have capabilities to read files, loop through them and resolve DNS host entries.
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText: "*Get-content *" AND ScriptBlockText: "*foreach*" AND ScriptBlockText: "*[System.Net.Dns]::GetHostEntry*" AND ScriptBlockText: "*Out-File*"))
