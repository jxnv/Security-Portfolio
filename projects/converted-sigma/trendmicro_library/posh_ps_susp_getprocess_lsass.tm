// Title: PowerShell Get-Process LSASS in ScriptBlock
// ID: 84c174ab-d3ef-481f-9c86-a50d0b8e3edb
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-04-23
// Tags: attack.credential-access, attack.t1003.001
// Description: Detects a Get-Process command on lsass process, which is in almost all cases a sign of malicious activity
// Converted by: Sigma Universal SIEM/EDR CLI

(ScriptBlockText: "*Get-Process lsass*")
